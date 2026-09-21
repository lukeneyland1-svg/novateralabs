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
