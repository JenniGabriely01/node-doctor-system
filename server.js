const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const router = express.Router();

const app = express();
const PORT = 3000;
/* Porta do banco de dados */
const MONGO_URI = 'mongodb://localhost:27017/mydatabase';

app.use(cors());
app.use(bodyParser.json());

/* Conexão com o banco de dados */
mongoose.connect(MONGO_URI, {
    useUnifiedTopology: true
})
    .then(() => console.log('Conectado ao MongoDB'))
    .catch(err => console.error('Erro ao conectar ao MongoDB', err));

/* Definindo o schema do Cliente */
const clienteSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    sobrenome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    telefone: { type: String, required: true },
});

/* Criando o modelo Cliente */
const Cliente = mongoose.model('Cliente', clienteSchema);

/* Definindo o schema do Usuário */
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// Middleware para criptografar a senha antes de salvar
userSchema.pre('save', async function (next) {
    const user = this;
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 10);
    }
    next();
});

/* Criando o modelo Usuário */
const User = mongoose.model('User', userSchema);

/* Criar usuário pré-cadastrado */
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

/* Rota de login */
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
            res.status(200).json({ message: 'Login bem-sucedido' });
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
    try {
        const clientes = await Cliente.find();
        res.status(200).json(clientes);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar clientes', error });
    }
});

/* Usando o router */
app.use(router);

/* Iniciando o servidor */
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
