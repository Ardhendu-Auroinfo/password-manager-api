const db = require('../config/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userController = {
    // Register new user
    async register(req, res) {
        const { email, password, password_hint } = req.body;

        if(!email || !password ) {
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

            // Generate salt and hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Insert new user
            const newUser = await db.query(
                `INSERT INTO users (
                    email, 
                    master_password_hash, 
                    master_password_salt, 
                    master_password_hint
                ) VALUES ($1, $2, $3, $4) 
                RETURNING id, email, created_at`,
                [email, hashedPassword, salt, password_hint]
            );

            // Create default vault for user
            await db.query(
                `INSERT INTO password_vaults (
                    user_id, 
                    name, 
                    encrypted_key
                ) VALUES ($1, $2, $3)`,
                [newUser.rows[0].id, 'My Vault', Buffer.from('default_key')] // You'll want to properly generate and encrypt this key
            );

            // Generate JWT
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
        const { email, password } = req.body;

        try {
            // Find user
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

            // Ensure password and hash are strings
            const storedHash = user.rows[0].master_password_hash.toString();
            const passwordString = String(password);

            // Verify password
            const validPassword = await bcrypt.compare(
                passwordString,
                storedHash
            );

            if (!validPassword) {
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

            res.json({
                success: true,
                data: {
                    user: {
                        id: user.rows[0].id,
                        email: user.rows[0].email
                    },
                    token
                }
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({
                success: false,
                message: 'Error logging in'
            });
        }
    }
};

module.exports = userController;