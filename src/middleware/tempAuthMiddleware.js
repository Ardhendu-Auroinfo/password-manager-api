const jwt = require('jsonwebtoken');

const tempAuthMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if this is a recovery token
        if (!decoded.recovery) {
            return res.status(401).json({ message: 'Invalid token type' });
        }

        req.user = { 
            id: decoded.user_id,
            isRecovery: true 
        };
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired session' });
    }
};

module.exports = tempAuthMiddleware;