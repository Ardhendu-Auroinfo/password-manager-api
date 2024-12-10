const express = require('express');
const router = express.Router();
const vaultController = require('../controllers/vaultController');
const { validateEntry } = require('../middleware/validationMiddleware');
const { authenticateToken } = require('../middleware/authMiddleware');

// All routes are protected with authentication
router.use(authenticateToken);

// Password entries routes
router.get('/entries', vaultController.getAllEntries);
router.post('/entries', validateEntry, vaultController.createEntry);
router.put('/entries/:id', validateEntry, vaultController.updateEntry);
router.delete('/entries/:id', vaultController.deleteEntry);
router.get('/entries/search', vaultController.searchEntries);
router.get('/entries/:id', vaultController.getEntryById);

module.exports = router; 