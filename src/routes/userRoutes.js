const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/forgot-password', userController.requestPasswordReset);
router.post('/verify-recovery', userController.verifyRecoveryToken);
router.post('/reset-password', userController.resetPassword);
router.post('/password-hint', userController.getPasswordHint);

module.exports = router;