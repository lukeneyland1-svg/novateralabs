const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const path = require('path');
const session = require('express-session');

const { SESSION_SECRET } = require('./secrets');

const dashboardRoutes = require('./server/routes/dashboard');
const securityRoutes = require('./server/routes/security');
const automationRoutes = require('./server/routes/automation');
const authRoutes = require('./server/routes/auth');
const contactRoutes = require('./server/routes/contact');
const breachRoutes = require('./server/routes/breach');
const simulationRoutes = require('./server/routes/simulation');
const ingestRoutes = require('./server/routes/ingest');
const billingRoutes = require('./server/routes/billing');
const scanRoutes = require('./server/routes/scan');
const statusRoutes = require('./server/routes/status');
const statusChecker = require('./services/statusChecker');
const complianceRoutes = require('./server/routes/compliance');
const apiV1Routes = require('./server/routes/apiV1');

const requireAuth = require('./middleware/requireAuth');
const requireAuthPage = require('./middleware/requireAuthPage');
const requireOwner = require('./middleware/requireOwner');
const requireSubscription = require('./middleware/requireSubscription');
const scheduler = require('./scheduler');

const app = express();
app.use(cors({ origin: true, credentials: true }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Mounted before the global express.json() below: the webhook route inside
// needs Stripe's raw, unparsed request body to verify its signature. Once
// express.json() has consumed a request body into a parsed object, the
// original bytes Stripe signed are gone — so this router (and its own
// express.raw(), scoped to just the webhook path) must see the request first.
// It still needs to come after the session middleware above, since its
// /checkout route reads req.session.
app.use('/api/billing', billingRoutes);

app.use(express.json());

app.get('/dashboard.html', requireAuthPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'protected', 'dashboard.html'));
});

// Explicit routes, not just a dropped-in file: express.static ignores
// dotfiles/dot-directories by default (confirmed by testing), so a file at
// public/.well-known/security.txt would silently 404. Serving it explicitly
// here — rather than turning on `dotfiles: 'allow'` for the static
// middleware below — means only this one intentional path is exposed,
// not every dotfile that might ever end up in public/.
app.get(['/.well-known/security.txt', '/security.txt'], (req, res) => {
  res.type('text/plain').sendFile(path.join(__dirname, '..', 'public', 'security.txt'));
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api/auth', authRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/breach-check', breachRoutes);
app.use('/api/dashboard', requireAuth, requireOwner, dashboardRoutes);
app.use('/api/security', requireAuth, requireOwner, securityRoutes);
app.use('/api/automation', requireAuth, requireSubscription, automationRoutes);
app.use('/api/simulation', requireAuth, requireOwner, simulationRoutes);
app.use('/api/ingest', ingestRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/status', statusRoutes);
app.use('/api/compliance', complianceRoutes);
app.use('/api/v1', apiV1Routes);

scheduler.loadAndScheduleAll();
statusChecker.start();

const HTTP_PORT = 80;
app.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`HTTP running on port ${HTTP_PORT}`);
});

const HTTPS_PORT = 443;
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'ssl', 'origin-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'ssl', 'origin-cert.pem')),
};
https.createServer(sslOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => {
  console.log(`HTTPS running on port ${HTTPS_PORT}`);
});
