const { body, validationResult } = require('express-validator');

const validateEntry = [
    body('title').trim().notEmpty().withMessage('Title is required'),
    body('username').optional().trim(),
    body('password').notEmpty().withMessage('Password is required'),
    body('website_url').optional().trim().isURL().withMessage('Invalid URL format'),
    body('category').optional().trim(),
    body('favorite').optional().isBoolean(),

    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];

module.exports = { validateEntry };