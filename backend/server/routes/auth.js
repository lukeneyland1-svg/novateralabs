const express = require("express");
const router = express.Router();
const authController = require("../../controllers/authController");
const mfaController = require("../../controllers/mfaController");
const requireAuth = require("../../middleware/requireAuth");
const rateLimitIp = require("../../middleware/rateLimitIp");

router.post("/login", rateLimitIp.login, authController.login);
router.post("/login/verify-mfa", rateLimitIp.mfa, authController.verifyMfaLogin);
router.post("/logout", authController.logout);
router.get("/session", authController.checkSession);
router.post("/forgot-password", rateLimitIp.forgotPassword, authController.requestPasswordReset);
router.post("/reset-password", rateLimitIp.resetPassword, authController.resetPassword);

router.post("/mfa/setup", requireAuth, mfaController.setupMfa);
router.post("/mfa/confirm", requireAuth, mfaController.confirmMfa);
router.post("/mfa/disable", requireAuth, mfaController.disableMfa);

module.exports = router;
