const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const User = require('./models/User'); // Certifique-se de que este arquivo exporta o modelo de usuário

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.DB || 'mongodb+srv://Hiq:Marchini08@mycluster.vxjsk.mongodb.net/OwlsLibrary?retryWrites=true&w=majority&appName=MyCluster';
const JWT_SECRET = process.env.JWTPRIVATEKEY || 'default_secret';
const SALT_ROUNDS = parseInt(process.env.SALT, 10) || 10;

app.use(cors({
    origin: 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => {
        console.log('Conectado ao MongoDB');
        createAdminUser(); // Função para criar o usuário admin ao conectar
    })
    .catch(err => console.error('Erro ao conectar ao MongoDB', err));

// Schemas
const clienteSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    sobrenome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    telefone: { type: String, required: true },
}, { timestamps: true });

const livroSchema = new mongoose.Schema({
    nomeLivro: { type: String, required: true },
    autor: { type: String, required: true },
    genero: { type: String, required: true },
    dataLancamento: { type: Date, required: true },
    qtdCopias: { type: Number, required: true, default: 1 },
    image: { type: String, required: true },
});

const emprestimoSchema = new mongoose.Schema({
    cliente: { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', required: true },
    livros: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Livro', required: true }],
    dataEmprestimo: { type: Date, default: Date.now },
});

const Emprestimo = mongoose.model('Emprestimo', emprestimoSchema);
const Cliente = mongoose.model('Cliente', clienteSchema);
const Livro = mongoose.model('Livro', livroSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

userSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
    }
    next();
});

const User = mongoose.model('User', userSchema); // Modelo para o usuário

// Função para criar o usuário admin
const createAdminUser = async () => {
    const adminEmail = "admin@example.com";
    const adminPassword = "adminpassword";

    try {
        const existingAdmin = await User.findOne({ email: adminEmail });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(adminPassword, SALT_ROUNDS);
            const adminUser = new User({ email: adminEmail, password: hashedPassword });
            await adminUser.save();
            console.log("Usuário admin criado com sucesso.");
        } else {
            console.log("Usuário admin já existe.");
        }
    } catch (error) {
        console.error("Erro ao criar usuário admin:", error);
    }
};

// Rota de login
app.post('/login', [
    body('email').isEmail().withMessage('Email inválido'),
    body('password').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (isPasswordValid) {
            const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ message: 'Login bem-sucedido', token });
        } else {
            res.status(400).json({ error: 'Email ou senha incorretos' });
        }
    } catch (error) {
        console.error('Erro ao autenticar usuário:', error);
        res.status(500).json({ error: 'Erro ao autenticar usuário' });
    }
});

// Middleware de autenticação
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token não fornecido' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido' });
        }
        req.user = decoded;
        next();
    });
};

// Rota para validar token
app.get('/validate', authMiddleware, (req, res) => {
    res.status(200).json({ message: 'Token válido', user: req.user });
});

// Rota para cadastrar cliente
app.post('/api/clientes', async (req, res) => {
    const { nome, sobrenome, email, telefone } = req.body;

    try {
        const clienteExistente = await Cliente.findOne({ email });
        if (clienteExistente) {
            return res.status(400).json({ message: 'E-mail já cadastrado.' });
        }

        const novoCliente = new Cliente({ nome, sobrenome, email, telefone });
        await novoCliente.save();

        res.status(201).json(novoCliente);
    } catch (error) {
        console.error('Erro ao cadastrar cliente:', error);
        if (error.code === 11000) {
            return res.status(400).json({ message: 'E-mail já cadastrado.' });
        }
        res.status(500).json({ message: "Erro ao cadastrar cliente", error });
    }
});

// Rota para buscar todos os clientes
app.get('/api/clientes', async (req, res) => {
    try {
        const clientes = await Cliente.find();
        res.json(clientes);
    } catch (error) {
        console.error('Erro ao buscar clientes:', error);
        res.status(500).json({ message: 'Erro ao buscar clientes' });
    }
});

// Rota para cadastrar livro
app.post('/api/livros', async (req, res) => {
    const { nomeLivro, autor, genero, dataLancamento, qtdCopias, image } = req.body;

    if (!nomeLivro || !autor || !genero || !dataLancamento || !qtdCopias || !image) {
        return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    }

    try {
        const novoLivro = new Livro({ nomeLivro, autor, genero, dataLancamento, qtdCopias, image });
        await novoLivro.save();
        res.status(201).json(novoLivro);
    } catch (error) {
        console.error('Erro ao cadastrar livro:', error);
        res.status(500).json({ message: "Erro ao cadastrar livro", error });
    }
});

// Rota para buscar livros
app.get('/api/livros', async (req, res) => {
    const { search } = req.query;

    try {
        const livros = search
            ? await Livro.find({
                $or: [
                    { nomeLivro: { $regex: search, $options: 'i' } },
                    { autor: { $regex: search, $options: 'i' } }
                ]
            })
            : await Livro.find();

        res.status(200).json(livros);
    } catch (error) {
        console.error('Erro ao buscar livros:', error);
        res.status(500).json({ message: 'Erro ao buscar livros' });
    }
});

// Rota para contar livros
app.get('/api/livros/count', async (req, res) => {
    try {
        const count = await Livro.countDocuments();
        res.status(200).json({ count });
    } catch (error) {
        console.error('Erro ao contar livros:', error);
        res.status(500).json({ message: 'Erro ao contar livros' });
    }
});

// Rota para contar livros emprestados
app.get('/api/livros/emprestados/count', async (req, res) => {
    try {
        const count = await Emprestimo.countDocuments();
        res.status(200).json({ count });
    } catch (error) {
        console.error('Erro ao contar livros emprestados:', error);
        res.status(500).json({ message: 'Erro ao contar livros emprestados' });
    }
});

// Rota para buscar todos os empréstimos
app.get('/api/emprestimos', async (req, res) => {
    try {
        const emprestimos = await Emprestimo.find()
            .populate('cliente', 'nome sobrenome')
            .populate('livros', 'nomeLivro');

        console.log('Empréstimos encontrados:', emprestimos); // Log para verificar os empréstimos

        res.json(emprestimos);
    } catch (error) {
        console.error('Erro ao buscar empréstimos:', error);
        res.status(500).json({ message: 'Erro ao buscar empréstimos' });
    }
});

// Rota para cadastrar empréstimos
app.post('/api/emprestimos', async (req, res) => {
    const { cliente, livros } = req.body;

    try {
        const novoEmprestimo = new Emprestimo({ cliente, livros });
        await novoEmprestimo.save();
        res.status(201).json(novoEmprestimo);
    } catch (error) {
        console.error('Erro ao realizar empréstimo:', error);
        res.status(500).json({ message: "Erro ao realizar empréstimo", error });
    }
});

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
