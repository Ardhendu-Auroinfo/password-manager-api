const db = require('../config/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const emailService = require('../services/emailService');
const userController = {
    // Register new user
    async register(req, res) {
        const { email, authKey, masterPasswordHint, encryptedVaultKey } = req.body;

        if (!email || !authKey || !encryptedVaultKey) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        try {
            // Check if user already exists
            const userExists = await db.query(
                'SELECT * FROM users WHERE email = $1',
                [email]
            );

            if (userExists.rows.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'User already exists'
                });
            }

            // Store user with auth key and encrypted vault key
            const newUser = await db.query(
                `INSERT INTO users (
                    email, 
                    auth_key,
                    master_password_hint,
                    encrypted_vault_key
                ) VALUES ($1, $2, $3, $4) 
                RETURNING id, email, created_at`,
                [email, authKey, masterPasswordHint, encryptedVaultKey]
            );

             // Create default vault for the new user
        await db.query(
            `INSERT INTO password_vaults (
                user_id, 
                name, 
                encrypted_key
            ) VALUES ($1, $2, $3)`,
                [newUser.rows[0].id, 'My Vault', Buffer.from('default_key')] // Replace with actual key generation logic
            );

            // Generate JWT (if needed)
            const token = jwt.sign(
                { user_id: newUser.rows[0].id },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(201).json({
                success: true,
                data: {
                    user: newUser.rows[0],
                    token
                }
            });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({
                success: false,
                message: 'Error registering user'
            });
        }
    },

    // Login user
    async login(req, res) {
        const { email, authKey } = req.body;

        try {
            // Find user by email
            const user = await db.query(
                'SELECT * FROM users WHERE email = $1',
                [email]
            );

            if (user.rows.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Check if account is locked
            if (user.rows[0].account_locked_until && 
                new Date(user.rows[0].account_locked_until) > new Date()) {
                return res.status(401).json({
                    success: false,
                    message: 'Account is locked. Please try again later.'
                });
            }
            
            // Convert provided authKey to hexadecimal
            const providedAuthKeyHex = Buffer.from(authKey, 'utf8').toString('hex');

            // Ensure authKey is valid
            const storedAuthKey = user.rows[0].auth_key.toString('hex'); // Assuming it's stored as a Buffer
            
            
            if (storedAuthKey !== providedAuthKeyHex) {
                // Increment failed login attempts
                await db.query(
                    `UPDATE users 
                    SET failed_login_attempts = failed_login_attempts + 1,
                        last_login_attempt = CURRENT_TIMESTAMP
                    WHERE id = $1`,
                    [user.rows[0].id]
                );

                // Check if we should lock the account (e.g., after 5 failed attempts)
                if (user.rows[0].failed_login_attempts >= 4) {
                    await db.query(
                        `UPDATE users 
                        SET account_locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
                        WHERE id = $1`,
                        [user.rows[0].id]
                    );
                }

                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Reset failed login attempts on successful login
            await db.query(
                `UPDATE users 
                SET failed_login_attempts = 0,
                    last_login_attempt = CURRENT_TIMESTAMP
                WHERE id = $1`,
                [user.rows[0].id]
            );

            // Create session
            const sessionResult = await db.query(
                `INSERT INTO user_sessions (
                    user_id,
                    token_hash,
                    device_info,
                    ip_address,
                    expires_at
                ) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP + INTERVAL '24 hours')
                RETURNING id`,
                [
                    user.rows[0].id,
                    'session_token', // You should generate a proper session token
                    JSON.stringify({ userAgent: req.headers['user-agent'] }),
                    req.ip
                ]
            );

            // Generate JWT
            const token = jwt.sign(
                { 
                    user_id: user.rows[0].id,
                    session_id: sessionResult.rows[0].id
                },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Include the encrypted vault key in the response
            const encryptedVaultKey = user.rows[0].encrypted_vault_key;

            // Ensure it's properly encoded before sending
            const encodedVaultKey = encryptedVaultKey.toString('utf8');

            res.json({
                success: true,
                data: {
                    user: {
                        id: user.rows[0].id,
                        email: user.rows[0].email
                    },
                    token,
                    encryptedVaultKey: encodedVaultKey
                }
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({
                success: false,
                message: 'Error logging in'
            });
        }
    },

    async requestPasswordReset(req, res) {
        const { email } = req.body;

        try {
            // Check if user exists
            const user = await db.query(
                'SELECT id, email FROM users WHERE email = $1',
                [email]
            );

            if (user.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No account found with this email'
                });
            }

            // Generate 6-digit recovery code
            const recoveryCode = Math.floor(100000 + Math.random() * 900000).toString();
            // Hash the recovery code before storing
            const recoveryCodeHash = await bcrypt.hash(recoveryCode, 10);

            // Store recovery code with expiration (1 hour)
            await db.query(
                `UPDATE users 
                SET recovery_token = $1,
                    recovery_token_expires = CURRENT_TIMESTAMP + INTERVAL '1 hour',
                    recovery_attempt_count = 0
                WHERE id = $2`,
                [recoveryCodeHash, user.rows[0].id]
            );

            // Send recovery email
            await emailService.sendPasswordRecovery(email, recoveryCode);

            res.json({
                success: true,
                message: 'Recovery code has been sent to your email'
            });

        } catch (error) {
            console.error('Password recovery request error:', error);
            res.status(500).json({
                success: false,
                message: 'Error processing recovery request'
            });
        }
    },

    async verifyRecoveryToken(req, res) {
        const { email, token } = req.body;

        try {
            const user = await db.query(
                `SELECT id, encrypted_vault_key, recovery_token, recovery_token_expires, recovery_attempt_count 
                FROM users WHERE email = $1`,
                [email]
            );

            if (user.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Invalid recovery attempt'
                });
            }

            const userData = user.rows[0];

            // Check if token is expired
            if (new Date(userData.recovery_token_expires) < new Date()) {
                return res.status(400).json({
                    success: false,
                    message: 'Recovery code has expired'
                });
            }

            // Check attempt count
            if (userData.recovery_attempt_count >= 3) {
                return res.status(400).json({
                    success: false,
                    message: 'Too many attempts. Please request a new recovery code'
                });
            }

            // Verify recovery code
            const isValidCode = await bcrypt.compare(token, userData.recovery_token);

            if (!isValidCode) {
                // Increment attempt count
                await db.query(
                    'UPDATE users SET recovery_attempt_count = recovery_attempt_count + 1 WHERE id = $1',
                    [userData.id]
                );

                return res.status(400).json({
                    success: false,
                    message: 'Invalid recovery code'
                });
            }

            // Generate temporary token for password reset
            const tempToken = jwt.sign(
                { user_id: userData.id, recovery: true },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
             // Include the encrypted vault key in the response
             const encryptedVaultKey = user.rows[0].encrypted_vault_key;

             // Ensure it's properly encoded before sending
             const encodedVaultKey = encryptedVaultKey.toString('utf8');

            res.json({
                success: true,
                tempToken,
                encryptedVaultKey: encodedVaultKey
            });

        } catch (error) {
            console.error('Recovery verification error:', error);
            res.status(500).json({
                success: false,
                message: 'Error verifying recovery code'
            });
        }
    },

    async resetPassword(req, res) {
        const client = await db.connect();
        try {
            const { authKey, encryptedVaultKey, reEncryptedEntries, email } = req.body;
            const userId = req.user.id; // From JWT verification
            
            await client.query('BEGIN');

            // Update user's auth key and vault key
            await client.query(
                'UPDATE users SET auth_key = $1, encrypted_vault_key = $2 WHERE email = $3',
                [authKey, encryptedVaultKey, email]
            );

            // Update all password entries with re-encrypted data
            for (const entry of reEncryptedEntries) {
                await client.query(
                    `UPDATE password_entries 
                     SET encrypted_username = $1, encrypted_password = $2, encrypted_notes = $3
                     WHERE id = $4 AND vault_id = $5`,
                    [
                        entry.encrypted_username, 
                        entry.encrypted_password, 
                        entry.encrypted_notes, 
                        entry.id,
                        userId
                    ]
                );
            }

            await client.query('COMMIT');
            res.json({ success: true });
        } catch (error) {
            await client.query('ROLLBACK');
            res.status(500).json({ success: false, message: error.message });
        } finally {
            client.release();
        }
    },

    async getPasswordHint(req, res) {
        const { email } = req.body;

        try {
            // Check if user exists and get hint
            const result = await db.query(
                'SELECT master_password_hint FROM users WHERE email = $1',
                [email]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'No account found with this email'
                });
            }

            const hint = result.rows[0].master_password_hint;

            if (!hint) {
                return res.status(404).json({
                    success: false,
                    message: 'No password hint set for this account'
                });
            }

            // Send email with fallback handling
            try {
                await emailService.sendPasswordHint(email, hint);
            } catch (emailError) {
                console.error('Email service error:', emailError);
                // Still return success if we found the hint
                // The email service will handle retries
            }

            res.json({
                success: true,
                message: 'Password hint has been sent to your email'
            });

        } catch (error) {
            console.error('Get password hint error:', error);
            res.status(500).json({
                success: false,
                message: 'Error retrieving password hint'
            });
        }
    }
};

module.exports = userController;