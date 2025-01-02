const jwt = require('jsonwebtoken');
const db = require('../config/database');

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        try {
            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // Check if user exists and is active
            const userQuery = `
                SELECT id, email, status 
                FROM users 
                WHERE id = $1 AND status = 'active'
            `;
            
            const userResult = await db.query(userQuery, [decoded.user_id]);

            const user = userResult.rows[0];
            
            if (!user || user.status !== 'active') {
                return res.status(401).json({ message: 'User not found or inactive' });
            }

            // Check session
            const sessionQuery = `
                SELECT * 
                FROM user_sessions 
                WHERE id = $1 
                AND user_id = $2 
                AND expires_at > CURRENT_TIMESTAMP
            `;
            
            const sessionResult = await db.query(sessionQuery, [
                decoded.session_id,
                decoded.user_id
            ]);

            if (sessionResult.rows.length === 0) {
                // Log all sessions for debugging
                const allSessions = await db.query(
                    'SELECT * FROM user_sessions WHERE user_id = $1',
                    [decoded.user_id]
                );
                
                return res.status(401).json({ message: 'Invalid or expired session' });
            }

            // Attach user and session to request
            req.user = user;
            req.session = sessionResult.rows[0];
            
            // Update last_used timestamp
            await db.query(
                'UPDATE user_sessions SET last_used = CURRENT_TIMESTAMP WHERE id = $1',
                [decoded.session_id]
            );

            next();
        } catch (err) {
            console.error('Token verification failed:', err);
            if (err.name === 'JsonWebTokenError') {
                return res.status(401).json({ message: 'Invalid token' });
            }
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expired' });
            }
            throw err;
        }
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

module.exports = { authenticateToken };