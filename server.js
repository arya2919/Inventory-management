const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');

const app = express();
const port = Number(process.env.PORT || 3000);
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'stockflow.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    default_threshold INTEGER NOT NULL DEFAULT 5 CHECK(default_threshold >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sku TEXT NOT NULL COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),
    cost_price REAL,
    selling_price REAL,
    low_stock_threshold INTEGER CHECK(low_stock_threshold IS NULL OR low_stock_threshold >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(organization_id, sku)
  );
`);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.dirname(dbPath) }),
  secret: process.env.SESSION_SECRET || 'local-development-only-change-before-deploy',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  if (req.method === 'POST') {
    const supplied = Buffer.from(String(req.body._csrf || ''));
    const expected = Buffer.from(req.session.csrfToken);
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      return res.status(403).render('error');
    }
  }
  next();
});

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});
const requireAuth = (req, res, next) => req.session.user ? next() : res.redirect('/login');
const flash = (req, type, message) => { req.session.flash = { type, message }; };
const clean = value => String(value ?? '').trim();
const parseOptionalMoney = value => value === '' || value == null ? null : Number(value);
const getProduct = (id, orgId) => db.prepare('SELECT * FROM products WHERE id = ? AND organization_id = ?').get(id, orgId);

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));
app.get('/signup', (req, res) => res.render('auth', { mode: 'signup', error: null }));
app.post('/signup', async (req, res, next) => {
  const name = clean(req.body.organization);
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || '');
  const confirm = String(req.body.confirm_password || '');
  if (!name || name.length > 80 || !/^\S+@\S+\.\S+$/.test(email) || email.length > 254 || password.length < 8 || password.length > 72 || password !== confirm) {
    return res.status(400).render('auth', { mode: 'signup', error: 'Enter a store name, a valid email, and matching passwords with at least 8 characters.' });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const createAccount = db.transaction(() => {
      const org = db.prepare('INSERT INTO organizations (name) VALUES (?)').run(name);
      const user = db.prepare('INSERT INTO users (organization_id, email, password_hash) VALUES (?, ?, ?)').run(org.lastInsertRowid, email, passwordHash);
      return { id: Number(user.lastInsertRowid), organization_id: Number(org.lastInsertRowid), email, organization: name };
    });
    req.session.regenerate(err => {
      if (err) return next(err);
      try { req.session.user = createAccount(); req.session.save(err2 => err2 ? next(err2) : res.redirect('/dashboard')); }
      catch (error) {
        if (String(error.code).includes('SQLITE_CONSTRAINT_UNIQUE')) return res.status(409).render('auth', { mode: 'signup', error: 'That email already has an account. Log in instead.' });
        next(error);
      }
    });
  } catch (error) { next(error); }
});
app.get('/login', (req, res) => res.render('auth', { mode: 'login', error: null }));
app.post('/login', async (req, res, next) => {
  const email = clean(req.body.email).toLowerCase();
  const account = db.prepare(`SELECT users.id, users.organization_id, users.email, users.password_hash, organizations.name AS organization
    FROM users JOIN organizations ON organizations.id = users.organization_id WHERE users.email = ?`).get(email);
  if (!account || !(await bcrypt.compare(String(req.body.password || ''), account.password_hash))) {
    return res.status(401).render('auth', { mode: 'login', error: 'Email or password is incorrect.' });
  }
  req.session.regenerate(err => {
    if (err) return next(err);
    req.session.user = { id: account.id, organization_id: account.organization_id, email: account.email, organization: account.organization };
    req.session.save(err2 => err2 ? next(err2) : res.redirect('/dashboard'));
  });
});
app.post('/logout', requireAuth, (req, res, next) => req.session.destroy(err => err ? next(err) : res.redirect('/login')));

app.get('/dashboard', requireAuth, (req, res) => {
  const orgId = req.session.user.organization_id;
  const organization = db.prepare('SELECT * FROM organizations WHERE id = ?').get(orgId);
  const products = db.prepare(`SELECT *, COALESCE(low_stock_threshold, ?) AS effective_threshold
    FROM products WHERE organization_id = ? ORDER BY quantity ASC, name COLLATE NOCASE ASC`).all(organization.default_threshold, orgId);
  const lowStock = products.filter(product => product.quantity <= product.effective_threshold);
  const totals = db.prepare('SELECT COUNT(*) AS product_count, COALESCE(SUM(quantity), 0) AS unit_count FROM products WHERE organization_id = ?').get(orgId);
  res.render('dashboard', { organization, products, lowStock, totals, active: 'dashboard' });
});

app.get('/products', requireAuth, (req, res) => {
  const orgId = req.session.user.organization_id;
  const query = clean(req.query.q).slice(0, 100);
  const products = query
    ? db.prepare(`SELECT * FROM products WHERE organization_id = ? AND (name LIKE ? OR sku LIKE ?) ORDER BY name COLLATE NOCASE`).all(orgId, `%${query}%`, `%${query}%`)
    : db.prepare('SELECT * FROM products WHERE organization_id = ? ORDER BY updated_at DESC, name COLLATE NOCASE').all(orgId);
  const org = db.prepare('SELECT default_threshold FROM organizations WHERE id = ?').get(orgId);
  res.render('products', { products, query, threshold: org.default_threshold, active: 'products' });
});
app.get('/products/new', requireAuth, (req, res) => res.render('product-form', { product: null, error: null, active: 'products' }));
app.post('/products', requireAuth, (req, res, next) => {
  const orgId = req.session.user.organization_id;
  const values = productValues(req.body);
  const error = validateProduct(values);
  if (error) return res.status(400).render('product-form', { product: values, error, active: 'products' });
  try {
    db.prepare(`INSERT INTO products (organization_id, name, sku, description, quantity, cost_price, selling_price, low_stock_threshold)
      VALUES (@organization_id, @name, @sku, @description, @quantity, @cost_price, @selling_price, @low_stock_threshold)`)
      .run({ ...values, organization_id: orgId });
    flash(req, 'success', 'Product added to your inventory.'); res.redirect('/products');
  } catch (err) {
    if (String(err.code).includes('SQLITE_CONSTRAINT_UNIQUE')) return res.status(409).render('product-form', { product: values, error: 'That SKU is already in use in your store.', active: 'products' });
    next(err);
  }
});
app.get('/products/:id/edit', requireAuth, (req, res) => {
  const product = getProduct(Number(req.params.id), req.session.user.organization_id);
  if (!product) return res.status(404).render('not-found');
  res.render('product-form', { product, error: null, active: 'products' });
});
app.post('/products/:id', requireAuth, (req, res, next) => {
  const orgId = req.session.user.organization_id;
  const current = getProduct(Number(req.params.id), orgId);
  if (!current) return res.status(404).render('not-found');
  const values = productValues(req.body);
  const error = validateProduct(values);
  if (error) return res.status(400).render('product-form', { product: { ...values, id: current.id }, error, active: 'products' });
  try {
    db.prepare(`UPDATE products SET name=@name, sku=@sku, description=@description, quantity=@quantity,
      cost_price=@cost_price, selling_price=@selling_price, low_stock_threshold=@low_stock_threshold,
      updated_at=CURRENT_TIMESTAMP WHERE id=@id AND organization_id=@organization_id`)
      .run({ ...values, id: current.id, organization_id: orgId });
    flash(req, 'success', 'Product changes saved.'); res.redirect('/products');
  } catch (err) {
    if (String(err.code).includes('SQLITE_CONSTRAINT_UNIQUE')) return res.status(409).render('product-form', { product: { ...values, id: current.id }, error: 'That SKU is already in use in your store.', active: 'products' });
    next(err);
  }
});
app.post('/products/:id/delete', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM products WHERE id = ? AND organization_id = ?').run(Number(req.params.id), req.session.user.organization_id);
  flash(req, result.changes ? 'success' : 'error', result.changes ? 'Product deleted.' : 'Product not found.');
  res.redirect('/products');
});

app.get('/settings', requireAuth, (req, res) => {
  const organization = db.prepare('SELECT * FROM organizations WHERE id = ?').get(req.session.user.organization_id);
  res.render('settings', { organization, active: 'settings' });
});
app.post('/settings', requireAuth, (req, res) => {
  const threshold = Number(req.body.default_threshold);
  if (!Number.isInteger(threshold) || threshold < 0 || threshold > 1000000) {
    flash(req, 'error', 'Enter a whole number from 0 to 1,000,000.'); return res.redirect('/settings');
  }
  db.prepare('UPDATE organizations SET default_threshold = ? WHERE id = ?').run(threshold, req.session.user.organization_id);
  flash(req, 'success', 'Default low stock threshold updated.'); res.redirect('/settings');
});

function productValues(body) {
  const money = key => clean(body[key]) === '' ? null : Number(body[key]);
  const thresholdText = clean(body.low_stock_threshold);
  return {
    name: clean(body.name).slice(0, 120), sku: clean(body.sku).slice(0, 64).toUpperCase(),
    description: clean(body.description).slice(0, 1000), quantity: Number(body.quantity),
    cost_price: money('cost_price'), selling_price: money('selling_price'),
    low_stock_threshold: thresholdText === '' ? null : Number(thresholdText)
  };
}
function validateProduct(p) {
  if (!p.name || !p.sku) return 'Product name and SKU are required.';
  if (!Number.isInteger(p.quantity) || p.quantity < 0 || p.quantity > 1000000000) return 'Quantity must be a whole number of 0 or more.';
  for (const amount of [p.cost_price, p.selling_price]) if (amount !== null && (!Number.isFinite(amount) || amount < 0 || amount > 1000000000)) return 'Prices must be valid non-negative amounts.';
  if (p.low_stock_threshold !== null && (!Number.isInteger(p.low_stock_threshold) || p.low_stock_threshold < 0 || p.low_stock_threshold > 1000000)) return 'Threshold must be a whole number of 0 or more.';
  return null;
}

app.use((req, res) => res.status(404).render('not-found'));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error');
});
app.listen(port, () => console.log(`StockFlow listening on ${port}`));
