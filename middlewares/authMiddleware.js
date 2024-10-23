const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWTPRIVATEKEY || 'default_secret';

const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(403).json({ error: 'Token não fornecido.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido.' });
        }
        req.user = decoded;
        next();
    });
};

module.exports = authMiddleware;
