const authMiddleware = (req, res, next) => {
    console.log('Cabeçalho recebido:', req.headers.authorization);
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        console.log('Token não fornecido');
        return res.status(401).json({ error: 'Token não fornecido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log('Erro ao validar token:', err.message);
            return res.status(403).json({ error: 'Token inválido ou expirado' });
        }
        req.userId = decoded.userId;
        next();
    });
};
