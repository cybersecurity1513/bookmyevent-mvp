const express = require("express");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("node:path");
const {
  createCsrfToken,
  hashPassword,
  hashPasswordSync,
  isValidEmail,
  tokensMatch,
  validatePassword,
  verifyPassword,
} = require("./security");
const { createSqliteSessionStore } = require("./database");

const categories = [
  "Photographer",
  "Decoration",
  "Catering",
  "DJ & Sound",
  "Makeup Artist",
  "Banquet Hall",
  "Event Planner",
  "Mehndi Artist",
  "Nail Artist",
];
const eventTypes = ["Wedding", "Birthday", "Corporate", "School / College", "Other"];
const phonePattern = /^[0-9+() -]{8,20}$/;
const allowedVendorStatuses = new Set(["pending", "approved", "rejected"]);
const maxAge = 8 * 60 * 60 * 1000;
const dummyPasswordHash = hashPasswordSync(require("node:crypto").randomBytes(32).toString("hex"));

function clean(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function validPhone(phone) {
  return phonePattern.test(phone);
}

function validDate(date) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return false;
  }
  const parsed = new Date(`${date}T00:00:00.000Z`);
  const dateParts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const today = `${dateParts.find((part) => part.type === "year").value}-${dateParts.find((part) => part.type === "month").value}-${dateParts.find((part) => part.type === "day").value}`;
  return !Number.isNaN(parsed.getTime())
    && parsed.toISOString().slice(0, 10) === date
    && date >= today;
}

function createApp({ db, sessionSecret, adminEmail, adminPassword, production = false, trustProxy = false }) {
  if (!db || !sessionSecret || sessionSecret.length < 32) {
    throw new Error("A database and a session secret of at least 32 characters are required.");
  }

  if (Boolean(adminEmail) !== Boolean(adminPassword)) {
    throw new Error("Set both adminEmail and adminPassword to bootstrap an administrator.");
  }
  if (adminEmail) {
    const normalizedEmail = adminEmail.trim().toLowerCase();
    if (!isValidEmail(normalizedEmail) || !validatePassword(adminPassword)) {
      throw new Error("Admin bootstrap credentials are invalid; use a valid email and a 12-128 character password.");
    }
    const existing = db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").get();
    if (!existing) {
      db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'admin')")
        .run(normalizedEmail, hashPasswordSync(adminPassword));
    }
  }

  const app = express();
  const sessionStore = createSqliteSessionStore(db);
  app.locals.sessionStore = sessionStore;
  if (trustProxy) {
    app.set("trust proxy", 1);
  }

  app.disable("x-powered-by");
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        imgSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        "upgrade-insecure-requests": production ? [] : null,
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  }));
  app.use(express.urlencoded({ extended: false, limit: "16kb" }));
  app.use(express.static(path.join(__dirname, "..", "public"), {
    dotfiles: "deny",
    index: false,
    maxAge: production ? "1h" : 0,
  }));
  app.use(session({
    name: "bme.sid",
    secret: sessionSecret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: production,
      sameSite: "lax",
      maxAge,
      path: "/",
    },
  }));
  app.use((req, res, next) => {
    if (!req.session.csrfToken) {
      req.session.csrfToken = createCsrfToken();
    }
    res.locals.csrfToken = req.session.csrfToken;
    res.locals.currentUser = req.session.user || null;
    res.locals.flash = req.session.flash || null;
    delete req.session.flash;
    res.locals.brand = "BookMyEvent";
    next();
  });
  const render = (res, view, data = {}) => res.render(view, {
    error: null,
    values: null,
    ...data,
  });
  const flash = (req, type, message) => {
    req.session.flash = { type, message };
  };
  const requireCsrf = (req, res, next) => {
    if (!tokensMatch(req.session.csrfToken, req.body?._csrf)) {
      res.status(403).render("error", {
        title: "Request expired",
        message: "Refresh the page and try again.",
      });
      return;
    }
    next();
  };
  const requireAuth = (req, res, next) => {
    if (!req.session.user) {
      flash(req, "error", "Please sign in to continue.");
      res.redirect("/login");
      return;
    }
    next();
  };
  const requireRole = (role) => (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      res.status(403).render("error", {
        title: "Access denied",
        message: "You do not have permission to perform this action.",
      });
      return;
    }
    next();
  };
  const limitRequests = (limit) => rateLimit({
    windowMs: 15 * 60 * 1000,
    limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (req, res) => res.status(429).render("error", {
      title: "Too many requests",
      message: "Please wait a while before trying again.",
    }),
  });

  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "..", "views"));

  app.get("/", (req, res) => {
    const q = clean(req.query.q, 80);
    const city = clean(req.query.city, 80);
    const category = categories.includes(req.query.category) ? req.query.category : "";
    const vendors = db.prepare(`
      SELECT id, name, category, city, price, description
      FROM vendors
      WHERE status = 'approved'
        AND (? = '' OR name LIKE ? OR category LIKE ? OR description LIKE ?)
        AND (? = '' OR lower(city) = lower(?))
        AND (? = '' OR category = ?)
      ORDER BY name
      LIMIT 60
    `).all(q, `%${q}%`, `%${q}%`, `%${q}%`, city, city, category, category);
    render(res, "index", { title: "Find event vendors", vendors, q, city, category, categories });
  });

  app.get("/register", (req, res) => {
    render(res, "register", { title: "Become a vendor", categories });
  });

  app.post("/register", limitRequests(5), requireCsrf, async (req, res, next) => {
    try {
      const email = clean(req.body.email, 254).toLowerCase();
      const password = req.body.password;
      const name = clean(req.body.name, 100);
      const category = clean(req.body.category, 50);
      const city = clean(req.body.city, 80);
      const contact = clean(req.body.contact, 100);
      const phone = clean(req.body.phone, 20);
      const price = Number(req.body.price);
      const description = clean(req.body.description, 1000);

      if (!isValidEmail(email) || !validatePassword(password) || name.length < 2
        || !categories.includes(category) || city.length < 2 || contact.length < 2
        || !validPhone(phone) || !Number.isSafeInteger(price) || price < 0
        || description.length < 10) {
        res.status(400).render("register", {
          title: "Become a vendor",
          categories,
          error: "Check every field. Passwords must be at least 12 characters; descriptions need at least 10 characters.",
          values: { email, name, category, city, contact, phone, price, description },
        });
        return;
      }

      const passwordHash = await hashPassword(password);
      db.exec("BEGIN IMMEDIATE");
      let userId;
      try {
        const result = db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'vendor')")
          .run(email, passwordHash);
        db.prepare(`
          INSERT INTO vendors (owner_user_id, name, category, city, contact, phone, price, description, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        `).run(result.lastInsertRowid, name, category, city, contact, phone, price, description);
        userId = Number(result.lastInsertRowid);
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      await establishSession(req, { id: userId, email, role: "vendor" });
      flash(req, "success", "Your vendor application is submitted and awaiting admin approval.");
      res.redirect("/dashboard");
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        res.status(409).render("register", {
          title: "Become a vendor",
          categories,
          error: "An account with that email already exists.",
          values: { ...req.body, password: undefined },
        });
        return;
      }
      next(error);
    }
  });

  app.get("/login", (req, res) => {
    render(res, "login", { title: "Sign in" });
  });

  app.post("/login", limitRequests(10), requireCsrf, async (req, res, next) => {
    try {
      const email = clean(req.body.email, 254).toLowerCase();
      const password = typeof req.body.password === "string" ? req.body.password : "";
      const user = db.prepare("SELECT id, email, password_hash, role FROM users WHERE email = ?").get(email);
      const passwordOk = await verifyPassword(password, user?.password_hash || dummyPasswordHash);
      if (!user || !passwordOk) {
        res.status(401).render("login", {
          title: "Sign in",
          error: "Email or password is incorrect.",
          values: { email },
        });
        return;
      }

      await establishSession(req, { id: user.id, email: user.email, role: user.role });
      res.redirect("/dashboard");
    } catch (error) {
      next(error);
    }
  });

  app.post("/logout", requireCsrf, (req, res, next) => {
    req.session.destroy((error) => {
      if (error) {
        next(error);
        return;
      }
      res.clearCookie("bme.sid", { httpOnly: true, secure: production, sameSite: "lax", path: "/" });
      res.redirect("/");
    });
  });

  app.get("/dashboard", requireAuth, (req, res) => {
    if (req.session.user.role === "admin") {
      const vendors = db.prepare("SELECT * FROM vendors ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC").all();
      const bookings = db.prepare(`
        SELECT b.*, v.name AS vendor_name
        FROM bookings b JOIN vendors v ON v.id = b.vendor_id
        ORDER BY b.created_at DESC LIMIT 200
      `).all();
      render(res, "admin-dashboard", { title: "Admin dashboard", vendors, bookings });
      return;
    }

    const vendor = db.prepare("SELECT * FROM vendors WHERE owner_user_id = ?").get(req.session.user.id);
    if (!vendor) {
      res.status(404).render("error", { title: "Profile not found", message: "Your vendor profile could not be found." });
      return;
    }
    const bookings = db.prepare("SELECT * FROM bookings WHERE vendor_id = ? ORDER BY created_at DESC").all(vendor.id);
    render(res, "vendor-dashboard", { title: "Vendor dashboard", vendor, bookings, categories });
  });

  app.post("/vendor/profile", requireAuth, requireRole("vendor"), requireCsrf, (req, res) => {
    const name = clean(req.body.name, 100);
    const category = clean(req.body.category, 50);
    const city = clean(req.body.city, 80);
    const contact = clean(req.body.contact, 100);
    const phone = clean(req.body.phone, 20);
    const price = Number(req.body.price);
    const description = clean(req.body.description, 1000);
    if (name.length < 2 || !categories.includes(category) || city.length < 2
      || contact.length < 2 || !validPhone(phone) || !Number.isSafeInteger(price)
      || price < 0 || description.length < 10) {
      flash(req, "error", "Profile details are invalid; please check the fields.");
      res.redirect("/dashboard");
      return;
    }
    db.prepare(`
      UPDATE vendors SET name = ?, category = ?, city = ?, contact = ?, phone = ?, price = ?, description = ?
      WHERE owner_user_id = ?
    `).run(name, category, city, contact, phone, price, description, req.session.user.id);
    flash(req, "success", "Your profile was updated.");
    res.redirect("/dashboard");
  });

  app.post("/vendors/:id/enquiries", limitRequests(8), requireCsrf, (req, res) => {
    const vendorId = Number(req.params.id);
    const vendor = Number.isSafeInteger(vendorId)
      ? db.prepare("SELECT id FROM vendors WHERE id = ? AND status = 'approved'").get(vendorId)
      : null;
    const customer = clean(req.body.customer, 100);
    const phone = clean(req.body.phone, 20);
    const eventDate = clean(req.body.event_date, 10);
    const city = clean(req.body.city, 80);
    const budget = req.body.budget === "" ? 0 : Number(req.body.budget);
    const eventType = clean(req.body.event_type, 40);
    const requirements = clean(req.body.requirements, 1000);
    if (!vendor || customer.length < 2 || !validPhone(phone) || !validDate(eventDate)
      || city.length < 2 || !Number.isSafeInteger(budget) || budget < 0
      || !eventTypes.includes(eventType)) {
      res.status(400).render("error", {
        title: "Enquiry not sent",
        message: "Check the enquiry fields and make sure the vendor is currently approved.",
      });
      return;
    }
    db.prepare(`
      INSERT INTO bookings (vendor_id, customer, phone, event_date, city, budget, event_type, requirements)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(vendor.id, customer, phone, eventDate, city, budget, eventType, requirements);
    req.session.flash = { type: "success", message: "Your enquiry was sent securely to the vendor." };
    res.redirect("/");
  });

  app.post("/admin/vendors/:id/status", requireAuth, requireRole("admin"), requireCsrf, (req, res) => {
    const id = Number(req.params.id);
    const status = clean(req.body.status, 20);
    if (!Number.isSafeInteger(id) || !allowedVendorStatuses.has(status)) {
      res.status(400).render("error", { title: "Invalid request", message: "That vendor action is not valid." });
      return;
    }
    const result = db.prepare("UPDATE vendors SET status = ? WHERE id = ?").run(status, id);
    if (!result.changes) {
      res.status(404).render("error", { title: "Vendor not found", message: "That vendor profile no longer exists." });
      return;
    }
    flash(req, "success", `Vendor status changed to ${status}.`);
    res.redirect("/dashboard");
  });

  app.post("/admin/bookings/:id/status", requireAuth, requireRole("admin"), requireCsrf, (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || !["New", "Contacted"].includes(req.body.status)) {
      res.status(400).render("error", { title: "Invalid request", message: "That enquiry action is not valid." });
      return;
    }
    const result = db.prepare("UPDATE bookings SET status = ? WHERE id = ?").run(req.body.status, id);
    if (!result.changes) {
      res.status(404).render("error", { title: "Enquiry not found", message: "That enquiry no longer exists." });
      return;
    }
    flash(req, "success", "Enquiry status updated.");
    res.redirect("/dashboard");
  });

  app.use((req, res) => {
    res.status(404).render("error", { title: "Page not found", message: "That page does not exist." });
  });

  app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) {
      next(error);
      return;
    }
    res.status(500).render("error", { title: "Something went wrong", message: "The request could not be completed." });
  });

  return app;
}

function establishSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }
      req.session.user = user;
      req.session.csrfToken = createCsrfToken();
      req.session.save((saveError) => saveError ? reject(saveError) : resolve());
    });
  });
}

module.exports = { createApp, categories, validDate, validPhone };
