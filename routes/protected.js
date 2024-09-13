const express = require('express');
const authMiddleware = require('../middlewares/authMiddleware');
const router = express.Router();

router.get('/data', authMiddleware, (req, res) => {
    res.status(200).json({ message: 'Dados protegidos', user: req.user });
});

module.exports = router;
