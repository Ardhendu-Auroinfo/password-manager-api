const express = require('express');
const router = express.Router();
const vaultController = require('../controllers/vaultController');
const shareController = require('../controllers/shareController');
const { validateEntry } = require('../middleware/validationMiddleware');
const { authenticateToken } = require('../middleware/authMiddleware');
const tempAuthMiddleware = require('../middleware/tempAuthMiddleware');

router.get('/entries-for-reset', tempAuthMiddleware, vaultController.getEntriesForReset);
// All routes are protected with authentication
router.use(authenticateToken);

// Password entries routes
router.get('/entries', vaultController.getAllEntries);
router.get('/entries/favorites', vaultController.getFavoriteEntries);
router.post('/entries', validateEntry, vaultController.createEntry);
router.put('/entries/:id', validateEntry, vaultController.updateEntry);
router.delete('/entries/:id', vaultController.deleteEntry);
router.get('/entries/search', vaultController.searchEntries);
router.get('/entries/:id', vaultController.getEntryById);

router.post('/share', shareController.sharePassword);
router.get('/shared-passwords', shareController.getSharedPasswords);
router.get('/shared-by-me', shareController.getSharedByMePasswords);
router.delete('/share/:id', shareController.revokeAccess);
router.put('/share/:id/permission', shareController.updatePermissionLevel);
router.put('/share/:id/expiry', shareController.updateExpiry);

module.exports = router; 