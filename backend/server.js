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

const requireAuth = require('./middleware/requireAuth');
const requireAuthPage = require('./middleware/requireAuthPage');
const requireOwner = require('./middleware/requireOwner');
const scheduler = require('./scheduler');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

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

app.get('/dashboard.html', requireAuthPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'protected', 'dashboard.html'));
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api/auth', authRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/breach-check', breachRoutes);
app.use('/api/dashboard', requireAuth, requireOwner, dashboardRoutes);
app.use('/api/security', requireAuth, requireOwner, securityRoutes);
app.use('/api/automation', requireAuth, automationRoutes);
app.use('/api/simulation', requireAuth, requireOwner, simulationRoutes);

scheduler.loadAndScheduleAll();

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
