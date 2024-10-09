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
    useUnifiedTopology: true,
    useNewUrlParser: true
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
    qtdCopias: { type: Number, required: true }, 
    image: { type: String, required: true },
});

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

/* Rota para buscar clientes */
router.get("/api/clientes", async (req, res) => {
    const { search } = req.query; // Obtém o termo de busca

    try {
        let query = {}; // Inializamos a query vazia

        // Se o termo de busca for concedido, adicionamos na query
        if (search) {
            query = {
                $or: [
                    {nome: {$regex: search, $options: 'i'} }, // Busca por nome
                    {sobrenome: {$regex: search, $options: 'i'} }, // Busca por sobrenome
                    {email: {$regex: search, $options: 'i'} }, // Busca por email
                ]
            };
        }

        // Consultamos o banco de dados com a query montada
        const clientes = await Cliente.find(query).sort({ createAt: -1 }); // Organiza por data de criação em ordem decrescente

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

router.get("/api/livros", async (req, res) => {
    const { search } = req.query; // Obtém o termo de busca
    console.log(`Recebido termo de busca: ${search}`);  // Log do termo recebido

    try {
        let query = {}; // Inicializamos a query vazia

        // Se o termo de busca for fornecido, adicionamos na query
        if (search) {
            query = {
                $or: [
                    { nomeLivro: { $regex: search, $options: 'i' } },  // Busca por nome do livro
                    { autor: { $regex: search, $options: 'i' } },      // Busca por autor
                    { genero: { $regex: search, $options: 'i' } },     // Busca por gênero
                ]
            };
        }

        console.log(`Query final:`, query); // Log da query final
        const livros = await Livro.find(query).sort({ createdAt: -1 });
        console.log(`Livros encontrados: ${livros.length}`); // Log do número de livros encontrados
        res.status(200).json(livros);
    } catch (error) {
        console.error('Erro ao buscar livros:', error); // Log do erro
        res.status(500).json({ message: 'Erro ao buscar livros', error });
    }
});


/* Usando o router */
app.use(router);

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
