const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.DB || 'mongodb://localhost:27017/mydatabase';
const JWT_SECRET = process.env.JWTPRIVATEKEY || 'default_secret';
const SALT_ROUNDS = parseInt(process.env.SALT, 10) || 10;

app.use(cors());
app.use(bodyParser.json());

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log('Conectado ao MongoDB'))
    .catch(err => console.error('Erro ao conectar ao MongoDB', err));

/* Definindo o schema do Cliente */
const clienteSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    sobrenome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    telefone: { type: Number, required: true },
}, { timestamps: true });

/* Definindo o schema do Livro */
const livroSchema = new mongoose.Schema({
    nomeLivro: { type: String, required: true },
    autor: { type: String, required: true },
    genero: { type: String, required: true },
    dataLancamento: { type: Date, required: true },
    qtdCopias: { type: Number, required: true, default: 1 },
    image: { type: String, required: true },
});

/* Definindo o schema do Emprestimo */
const emprestimoSchema = new mongoose.Schema({
    cliente: { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', required: true },
    livros: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Livro', required: true }],
    dataEmprestimo: { type: Date, default: Date.now },
});

/* Criando o modelo Emprestimo*/
const Emprestimo = mongoose.model('Emprestimo', emprestimoSchema);

/* Criando o modelo Cliente */
const Cliente = mongoose.model('Cliente', clienteSchema);

/* Criando o modelo do Livro */
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

/* Rota para cadastrar cliente */
router.post('/api/clientes', async (req, res) => {
    const { nome, sobrenome, email, telefone } = req.body;
    try {
        const novoCliente = new Cliente({ nome, sobrenome, email, telefone });
        await novoCliente.save();
        res.status(201).json(novoCliente);
    } catch (error) {
        res.status(400).json({ message: "Erro ao cadastrar cliente", error });
    }
});

/* Rota para obter clientes */
router.get("/api/clientes", async (req, res) => {
    const { limit } = req.query;
    try {
        let clientes;
        // Se "limit" estiver definido, limitamos o número de clientes
        //  A função .sort({ createdAt: -1 }) organiza os clientes pelo campo de criação em ordem decrescente
        if (limit) {
            clientes = await Cliente.find().sort({ createdAt: -1 }).limit(parseInt(limit));
        } else {
            clientes = await Cliente.find().sort({ createdAt: -1 }); // Caso contrário, retorna todos
        }
        res.status(200).json(clientes);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar clientes', error });
    }
});

/* Rota para cadastrar livro */
router.post('/api/livros', async (req, res) => {
    const { nomeLivro, autor, genero, dataLancamento, qtdCopias, image } = req.body;

    // Verificando os dados recebidos
    console.log('Dados recebidos no POST /api/livros:', req.body);

    try {
        const novoLivro = new Livro({ nomeLivro, autor, genero, dataLancamento, qtdCopias, image });
        await novoLivro.save();
        res.status(201).json(novoLivro);
    } catch (error) {
        res.status(400).json({ message: "Erro ao cadastrar livro", error });
    }
});

/* Rota para obter livros */
router.get("/api/livros", async (req, res) => {
    try {
        const livros = await Livro.find();
        res.status(200).json(livros);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar livros', error });
    }
});

/* Rota para cadastrar empréstimo */
router.post('/api/emprestimos', async (req, res) => {
    const { cliente, livros, dataEmprestimo } = req.body;

    if (!cliente || !livros || !Array.isArray(livros) || livros.length === 0) {
        return res.status(400).json({ message: 'Cliente e pelo menos um livro são obrigatórios.' });
    }

    try {
        const clienteExistente = await Cliente.findById(cliente);
        if (!clienteExistente) {
            return res.status(404).json({ message: 'Cliente não encontrado.' });
        }

        const livrosUnicos = [...new Set(livros)];
        if (livrosUnicos.length !== livros.length) {
            return res.status(400).json({ message: 'Livros duplicados não são permitidos.' });
        }

        const livrosEncontrados = await Livro.find({ _id: { $in: livrosUnicos } });
        if (livrosEncontrados.length !== livrosUnicos.length) {
            return res.status(404).json({ message: 'Um ou mais livros não foram encontrados.' });
        }

        const indisponiveis = livrosEncontrados.filter(livro => livro.qtdCopias < 1);
        if (indisponiveis.length > 0) {
            return res.status(400).json({
                message: 'Alguns livros não estão disponíveis para empréstimo.',
                livros: indisponiveis.map(livro => livro.nomeLivro)
            });
        }

        // Atualizar a quantidade de cópias disponíveis
        await Promise.all(livrosEncontrados.map(livro => {
            livro.qtdCopias -= 1;
            return livro.save();
        }));

        // Criar o empréstimo
        const novoEmprestimo = new Emprestimo({ cliente, livros: livrosUnicos, dataEmprestimo });
        await novoEmprestimo.save();

        return res.status(201).json(novoEmprestimo);
    } catch (error) {
        console.error('Erro no processo de criação de empréstimo:', error);
        return res.status(500).json({ message: 'Erro ao criar empréstimo', error: error.message });
    }
});


/* Rota para obter empréstimos */
router.get('/api/emprestimos', async (req, res) => {
    try {
        const emprestimos = await Emprestimo.find()
            .populate('cliente')
            .populate('livros')
            .sort({ data: -1 });
        res.status(200).json(emprestimos);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar empréstimos.', error });
    }
});

/* Usando o router */
app.use(router);

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
