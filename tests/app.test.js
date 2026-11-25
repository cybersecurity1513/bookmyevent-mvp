const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const { createDatabase } = require("../src/database");
const { createApp } = require("../src/app");

function createTestApp() {
  const db = createDatabase(":memory:");
  const app = createApp({
    db,
    sessionSecret: "test-session-secret-that-is-long-enough-123456",
    adminEmail: "admin@example.com",
    adminPassword: "Admin-Test-Password-123!",
  });
  return { app, db };
}

function csrfFrom(response) {
  const match = response.text.match(/name="_csrf" value="([^"]+)"/);
  assert.ok(match, "expected a CSRF token in the form");
  return match[1];
}

test("public listings are searchable and enquiry forms require a CSRF token", async (t) => {
  const { app, db } = createTestApp();
  t.after(() => {
    app.locals.sessionStore.close();
    db.close();
  });

  const home = await request(app).get("/?city=Meerut&category=Photographer");
  assert.equal(home.status, 200);
  assert.match(home.text, /The Wedding Frames/);
  assert.doesNotMatch(home.text, /Dream Decor Studio/);
  assert.match(home.headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.equal(home.headers["x-content-type-options"], "nosniff");

  const response = await request(app).post("/vendors/1/enquiries").type("form").send({
    customer: "Test Customer",
    phone: "9876543210",
    event_date: "2027-01-20",
    city: "Meerut",
    budget: "10000",
    event_type: "Wedding",
  });
  assert.equal(response.status, 403);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM bookings").get().count, 0);
});

test("vendor registration is pending, escaped, and cannot perform admin actions", async (t) => {
  const { app, db } = createTestApp();
  t.after(() => {
    app.locals.sessionStore.close();
    db.close();
  });

  const vendorAgent = request.agent(app);
  const registerPage = await vendorAgent.get("/register");
  const token = csrfFrom(registerPage);
  const registration = await vendorAgent.post("/register").type("form").send({
    _csrf: token,
    email: "vendor@example.com",
    password: "Vendor-Password-123!",
    name: "<script>alert(1)</script>",
    category: "Photographer",
    city: "Meerut",
    contact: "Vendor Person",
    phone: "9876543210",
    price: "5000",
    description: "A sample photography business description.",
  });
  assert.equal(registration.status, 302);
  const dashboard = await vendorAgent.get("/dashboard");
  assert.equal(dashboard.status, 200);
  assert.match(dashboard.text, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);

  const vendorToken = csrfFrom(dashboard);
  const forbidden = await vendorAgent.post("/admin/vendors/1/status").type("form").send({
    _csrf: vendorToken,
    status: "approved",
  });
  assert.equal(forbidden.status, 403);
  const publicPage = await request(app).get("/");
  assert.doesNotMatch(publicPage.text, /alert\(1\)/);
});

test("admin login, approval, and role-protected enquiry management work", async (t) => {
  const { app, db } = createTestApp();
  t.after(() => {
    app.locals.sessionStore.close();
    db.close();
  });

  const vendorAgent = request.agent(app);
  const registerPage = await vendorAgent.get("/register");
  await vendorAgent.post("/register").type("form").send({
    _csrf: csrfFrom(registerPage),
    email: "vendor@example.com",
    password: "Vendor-Password-123!",
    name: "Secure Vendor",
    category: "Catering",
    city: "Meerut",
    contact: "Vendor Person",
    phone: "9876543210",
    price: "9000",
    description: "Reliable catering services for private celebrations.",
  });

  const adminAgent = request.agent(app);
  const loginPage = await adminAgent.get("/login");
  const login = await adminAgent.post("/login").type("form").send({
    _csrf: csrfFrom(loginPage),
    email: "admin@example.com",
    password: "Admin-Test-Password-123!",
  });
  assert.equal(login.status, 302);
  const adminDashboard = await adminAgent.get("/dashboard");
  assert.match(adminDashboard.text, /Secure Vendor/);
  const adminToken = csrfFrom(adminDashboard);
  const vendorId = db.prepare("SELECT id FROM vendors WHERE name = 'Secure Vendor'").get().id;
  const approval = await adminAgent.post(`/admin/vendors/${vendorId}/status`).type("form").send({
    _csrf: adminToken,
    status: "approved",
  });
  assert.equal(approval.status, 302);
  assert.match((await request(app).get("/")).text, /Secure Vendor/);

  const customerAgent = request.agent(app);
  const home = await customerAgent.get("/");
  const enquiry = await customerAgent.post(`/vendors/${vendorId}/enquiries`).type("form").send({
    _csrf: csrfFrom(home),
    customer: "Event Customer",
    phone: "9876543211",
    event_date: "2027-02-01",
    city: "Meerut",
    budget: "25000",
    event_type: "Wedding",
    requirements: "Vegetarian menu",
  });
  assert.equal(enquiry.status, 302);
  const vendorDashboard = await vendorAgent.get("/dashboard");
  assert.match(vendorDashboard.text, /Event Customer/);
  assert.match(vendorDashboard.text, /Vegetarian menu/);

  const secondVendor = request.agent(app);
  const secondRegisterPage = await secondVendor.get("/register");
  await secondVendor.post("/register").type("form").send({
    _csrf: csrfFrom(secondRegisterPage),
    email: "other-vendor@example.com",
    password: "Other-Vendor-Password-123!",
    name: "Other Vendor",
    category: "Decoration",
    city: "Delhi",
    contact: "Another Person",
    phone: "9876543212",
    price: "7000",
    description: "Event decoration and flower arrangements.",
  });
  const otherDashboard = await secondVendor.get("/dashboard");
  assert.doesNotMatch(otherDashboard.text, /Event Customer/);
});
