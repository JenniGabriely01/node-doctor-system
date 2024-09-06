const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Para carregar variáveis de ambiente

const app = express();
const PORT = 3000;
const MONGO_URI = 'mongodb://localhost:27017/mydatabase';

app.use(cors());
app.use(bodyParser.json());

mongoose.connect(MONGO_URI, {
    useUnifiedTopology: true
})
.then(() => console.log('Conectado ao MongoDB'))
.catch(err => console.error('Erro ao conectar ao MongoDB', err));

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

userSchema.pre('save', async function(next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 10);
    }
    next();
});

const User = mongoose.model('User', userSchema);

async function criarUsuario() {
    const email = 'admin@example.com';
    const plainPassword = 'adminpassword';

    try {
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            const newUser = new User({ email, password: plainPassword });
            await newUser.save();
            console.log('Usuário pré-cadastrado criado com sucesso');
        } else {
            console.log('Usuário já existe');
        }
    } catch (error) {
        console.error('Erro ao criar usuário pré-cadastrado:', error);
    }
}

criarUsuario();

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Inserir todos os campos' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (isPasswordValid) {
            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ message: 'Login bem-sucedido', token });
        } else {
            res.status(400).json({ error: 'Email ou senha incorretos' });
        }
    } catch (error) {
        console.error('Erro ao autenticar usuário:', error);
        res.status(500).json({ error: 'Erro ao autenticar usuário' });
    }
});

// Middleware para verificar o token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ error: 'Token não fornecido' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
}

// Rota pública
app.get('/public', (req, res) => {
    res.status(200).json({ message: 'Essa é uma rota pública' });
});

// Rota protegida
app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Acesso concedido', user: req.user });
});

// Rota protegida com autenticação
app.get('/home', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Essa é uma rota protegida' });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
