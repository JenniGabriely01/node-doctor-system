const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const router = express.Router();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.DB || 'mongodb://localhost:27017/mydatabase';
const JWT_SECRET = process.env.JWTPRIVATEKEY || 'default_secret';
const SALT_ROUNDS = parseInt(process.env.SALT, 10) || 10;

/* Constantes para envio de e-mail */
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://developers.google.com/oauthplayground';
const REFRESH_TOKEN = '1//04QmSCgMMlsKPCgYIARAAGAQSNwF-L9Ir0Th4bNjzJD6-X5be4V0iR0D1mH602HtgN-jHIGiHQhQnQ1ANizpiG0dzI_nrW5CKMNc';

const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN })

app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json({ limit: '100mb' }));

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
    isbn: { type: String, required: true },
    editora: { type: String, required: true },
    dataLancamento: { type: Date, required: true },
    qtdCopias: { type: Number, required: true, default: 1 },
    image: { type: String, required: true },
});

/* Definindo o schema do Emprestimo */
const emprestimoSchema = new mongoose.Schema({
    cliente: { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', required: true },
    livros: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Livro', required: true }],
    dataEmprestimo: { type: Date, default: Date.now },
    devolvido: { type: Boolean, default: false },
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


const codeMap = new Map(); // Armazena códigos temporários

const recoverySchema = new mongoose.Schema({
    email: { type: String, required: true },
    codigo: { type: Number, required: true },
    expiraEm: { type: Date, required: true }
});
const Recovery = mongoose.model('Recovery', recoverySchema);


/* async function criarUsuario() {
    try {
        const email = "usuario@email.com";
        const senha = "senha123";

        // Verifique se o email já existe
        const usuarioExistente = await User.findOne({ email });
        if (usuarioExistente) {
            console.log("Usuário com este email já existe:", usuarioExistente);
            return;
        }

        // Criptografar a senha
        const senhaCriptografada = await bcrypt.hash(senha, 10);

        // Inserir o novo usuário
        const novoUsuario = new User({ email, password: senhaCriptografada });
        await novoUsuario.save();
        console.log("Usuário criado com sucesso!");
    } catch (error) {
        console.error("Erro ao criar usuário:", error);
    }
}

criarUsuario();
 */




/* async function criarUsuarioCorreto() {
    const bcrypt = require("bcrypt");
    const senha = "senha123"; // Substitua pela senha desejada

    const senhaCriptografada = await bcrypt.hash(senha, 10);
    console.log("Senha criptografada:", senhaCriptografada);

    // Substitua a senha do usuário existente no banco
    const usuarioAtualizado = await User.findOneAndUpdate(
        { email: "usuario@email.com" },
        { password: senhaCriptografada },
        { new: true }
    );

    console.log("Usuário atualizado com sucesso:", usuarioAtualizado);
}

criarUsuarioCorreto();
 */



/* === login === */
// Rota de login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    console.log("Tentativa de login:", { email, password });

    if (!email || !password) {
        return res.status(400).json({ error: "Email e senha são obrigatórios." });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.log("Usuário não encontrado.");
            return res.status(404).json({ error: "Usuário não encontrado." });
        }

        console.log("Hash armazenado no banco:", user.password);

        const isPasswordValid = await bcrypt.compare(password, user.password);
        console.log("Senha válida:", isPasswordValid);

        if (!isPasswordValid) {
            return res.status(400).json({ error: "Email ou senha incorretos." });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
        res.status(200).json({ message: "Login bem-sucedido.", token });
    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ error: "Erro interno no servidor." });
    }
});

/* === fim do login ==== */
app.post('/api/enviar-codigo', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "O campo de email é obrigatório." });
    }

    try {
        const usuarioExistente = await User.findOne({ email });
        if (!usuarioExistente) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }

        const codigo = Math.floor(100000 + Math.random() * 900000); // Gera um código de 6 dígitos
        const expiraEm = new Date(Date.now() + 10 * 60 * 1000); // Expira em 10 minutos

        // Salvar o código de recuperação no banco
        await Recovery.findOneAndUpdate(
            { email },
            { email, codigo, expiraEm },
            { upsert: true, new: true }
        );

        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: email,
            subject: 'Código de Recuperação',
            text: `Seu código de recuperação é: ${codigo}. Este código expira em 10 minutos.`,
        };

        await sendMail(mailOptions);
        res.status(200).json({ message: 'Código enviado com sucesso!' });
    } catch (error) {
        console.error('Erro ao enviar o código:', error);
        res.status(500).json({ error: 'Erro interno ao enviar o código.' });
    }
});

app.post('/api/redefinir-senha', async (req, res) => {
    const { email, codigo, novaSenha } = req.body;
    console.log('Recebendo requisição para redefinir senha:', req.body);

    if (!email || !codigo || !novaSenha) {
        console.log('Campos ausentes na requisição.');
        return res.status(400).json({ error: "Todos os campos são obrigatórios." });
    }

    try {
        const registroRecuperacao = await Recovery.findOne({ email, codigo });
        console.log('Registro de recuperação encontrado:', registroRecuperacao);

        if (!registroRecuperacao) {
            return res.status(400).json({ error: "Código inválido." });
        }

        if (registroRecuperacao.expiraEm < Date.now()) {
            return res.status(400).json({ error: "Código expirado." });
        }

        const senhaCriptografada = await bcrypt.hash(novaSenha, SALT_ROUNDS);
        console.log('Nova senha criptografada gerada.');

        const usuarioAtualizado = await User.findOneAndUpdate(
            { email },
            { password: senhaCriptografada },
            { new: true }
        );

        if (!usuarioAtualizado) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }

        await Recovery.deleteOne({ email, codigo });
        res.status(200).json({ message: "Senha alterada com sucesso!" });
    } catch (error) {
        console.error('Erro ao redefinir senha:', error);
        res.status(500).json({ error: "Erro interno ao redefinir senha." });
    }
});



/* === logica envio de e-mail === */
/* Função para envio de e-mail */
async function sendMail(mailOptions) {
    try {
        const accessToken = await oAuth2Client.getAccessToken();

        const transport = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: 'OAuth2',
                user: 'owlslibrarysuporte@gmail.com',
                clientId: CLIENT_ID,
                clientSecret: CLIENT_SECRET,
                refreshToken: REFRESH_TOKEN,
                accessToken: accessToken
            }
        });

        const result = await transport.sendMail(mailOptions);
        return result;

    } catch (error) {
        console.log("Erro ao enviar e-mail", error);
        throw error; // Lançar o erro para lidar com ele na rota, caso ocorra
    }
}
/* === fim rota de e-mail === */

/* === rotas para o dashboard ===*/
// Rota para obter os autores mais emprestados com numeração 
router.get('/api/autores-principais', async (req, res) => {
    try {
        const autoresQueMaisSaem = await Emprestimo.aggregate([
            { $unwind: "$livros" },
            {
                $lookup: {
                    from: "livros",
                    localField: "livros",
                    foreignField: "_id",
                    as: "livrosInfo"
                }
            },
            { $unwind: "$livrosInfo" },
            { $group: { _id: "$livrosInfo.autor", totalEmprestimos: { $sum: 1 } } },
            { $sort: { totalEmprestimos: -1 } },
            { $limit: 4 }
        ]);

        // Adicionando numeração a cada item do array de gêneros
        const autoresNumerados = autoresQueMaisSaem.map((autor, index) => ({
            posicao: index + 1,
            autor: autor._id,
            totalEmprestimos: autor.totalEmprestimos
        }));

        res.status(200).json(autoresNumerados);
    } catch (error) {
        console.error('Erro ao buscar autores mais emprestados:', error);
        res.status(500).json({ message: 'Erro ao buscar autores mais emprestados', error });
    }
})

// Rota para obter os gêneros mais emprestados com numeração
router.get('/api/generos-principais', async (req, res) => {
    try {
        const generosMaisEmprestados = await Emprestimo.aggregate([
            { $unwind: "$livros" },
            {
                $lookup: {
                    from: "livros",
                    localField: "livros",
                    foreignField: "_id",
                    as: "livroInfo"
                }
            },
            { $unwind: "$livroInfo" },
            { $group: { _id: "$livroInfo.genero", totalEmprestimos: { $sum: 1 } } },
            { $sort: { totalEmprestimos: -1 } },
            { $limit: 4 } // Número de gêneros a ser exibido
        ]);

        // Adicionando numeração a cada item do array de gêneros
        const generosNumerados = generosMaisEmprestados.map((genero, index) => ({
            posicao: index + 1,
            genero: genero._id,
            totalEmprestimos: genero.totalEmprestimos
        }));

        res.status(200).json(generosNumerados);
    } catch (error) {
        console.error('Erro ao buscar gêneros mais emprestados:', error);
        res.status(500).json({ message: 'Erro ao buscar gêneros mais emprestados', error });
    }
});

router.get('/api/clientes-principais', async (req, res) => {
    try {
        const clientesQueMaisEmprestam = await Emprestimo.aggregate([
            { $unwind: "$cliente" },
            {
                $lookup: {
                    from: 'clientes',
                    localField: 'cliente',
                    foreignField: '_id',
                    as: 'clienteInfo'
                }
            },
            { $unwind: "$clienteInfo" },
            { $group: { _id: "$clienteInfo.nome", totalClientes: { $sum: 1 } } },
            { $sort: { totalClientes: -1 } },
            { $limit: 4 }
        ]);


        const clienteNumerados = clientesQueMaisEmprestam.map((cliente, index) => ({
            posicao: index + 1,
            cliente: cliente._id,
            totalClientes: cliente.totalClientes
        }));

        res.status(200).json(clienteNumerados);
    } catch (error) {
        console.error('Erro ao buscar clientes:', error);
        res.status(500).json({ message: 'Erro ao buscar clientes', error });
    }
});

// Rota para contar empréstimos da última semana
router.get('/api/emprestimos/last-week-count', async (req, res) => {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    try {
        const count = await Emprestimo.countDocuments({ dataEmprestimo: { $gte: oneWeekAgo } });
        res.status(200).json({ count });
    } catch (error) {
        console.error('Erro ao contar empréstimos da última semana:', error);
        res.status(500).json({ message: 'Erro ao contar empréstimos da última semana', error });
    }
});

app.get('/api/livros-mais-emprestados', async (req, res) => {
    try {
        const livrosMaisEmprestados = await Emprestimo.aggregate([
            { $unwind: '$livros' }, // Desenrola o array de livros
            { $group: { _id: '$livros', count: { $sum: 1 } } }, // Agrupa por ID do livro
            { $sort: { count: -1 } }, // Ordena do mais emprestado para o menos
            { $limit: 4 },
            {
                $lookup: {
                    from: 'livros', // Nome correto da coleção de livros
                    localField: '_id',
                    foreignField: '_id',
                    as: 'livro',
                },
            },
            { $unwind: '$livro' }, // Desenrola o livro
        ]);
        res.json(livrosMaisEmprestados);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/livros-emprestados-semana', async (req, res) => {
    const seteDiasAtras = new Date();
    seteDiasAtras.setDate(seteDiasAtras.getDate() - 7);

    try {
        const livrosUltimos7Dias = await Emprestimo.aggregate([
            { $match: { dataEmprestimo: { $gte: seteDiasAtras } } },
            { $unwind: '$livros' }, // Desenrola o array de livros
            { $group: { _id: '$livros', count: { $sum: 1 } } }, // Agrupa por ID do livro
            { $lookup: { from: 'livros', localField: '_id', foreignField: '_id', as: 'livro' } },
            { $unwind: '$livro' },
            { $limit: 4 },

        ]);
        res.json(livrosUltimos7Dias);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/livros-menos-emprestados', async (req, res) => {
    try {
        const livrosMenosEmprestados = await Emprestimo.aggregate([
            { $unwind: '$livros' }, // Desenrola o array de livros
            { $group: { _id: '$livros', count: { $sum: 1 } } }, // Agrupa por ID do livro
            { $sort: { count: 1 } }, // Ordena do menor para o maior
            { $limit: 4 },
            {
                $lookup: {
                    from: 'livros',
                    localField: '_id',
                    foreignField: '_id',
                    as: 'livro',
                },
            },
            { $unwind: '$livro' }, // Desenrola o livro
        ]);
        res.json(livrosMenosEmprestados);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Rota para contar todos os empréstimos atrasados
router.get('/api/emprestimos/atrasos-total', async (req, res) => {
    try {
        // Contar todos os empréstimos não devolvidos
        const atrasos = await Emprestimo.countDocuments({
            devolvido: false
        });

        res.status(200).json({ count: atrasos });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao contar empréstimos em atraso', error });
    }
});
/* ==== fim dashboard ==== */


/* === página de clientes === */
/* Rota para cadastrar cliente */
router.post('/api/clientes', async (req, res) => {
    const { nome, sobrenome, email, telefone } = req.body;
    try {
        const clientesExistentes = await Cliente.findOne({
            $or: [{ nome }, { email }]
        });

        if (clientesExistentes) {
            return res.status(400).json({ message: 'Cliente já cadastrado com este nome ou e-mail' })
        }

        const novoCliente = new Cliente({ nome, sobrenome, email, telefone });
        await novoCliente.save();
        // Configurar as opções de e-mail com os dados do cliente
        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: email,
            cc: 'owlslibrarysuporte@gmail.com',
            subject: 'Bem-vindo à nossa plataforma!',
            html: `
                <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; color: #000;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="font-size: 24px; color: #000; margin-bottom: 16px; text-align: left;">Bem-vindo, ${nome}!</h1>
                        <hr style="margin: 10px 0; border: 0; height: 1px; background-color: #000;">
                        <p style="line-height: 1.6; color: #000; font-size: 16px; margin-bottom: 16px;">
                            Estamos felizes em informar que seu cadastro foi realizado com sucesso. <br>
                            Agora você faz parte de nossa comunidade e poderá usufruir de nossos serviços, como empréstimo de livros e acesso a novidades da biblioteca.
                        </p>
                        <p style=" color: #000; font-size: 16px;">Em caso de dúvidas, estamos à disposição. Boas leituras!</p>
                        <p style=" color: #000; font-size: 16px;">
                            Atenciosamente, <br>
                            Equipe Owl's Library.
                        </p>
                    </div>
                    <footer style="max-width: 600px; margin: 20px auto; text-align: left; font-size: 14px;">
                        <hr style="margin: 10px 0; border: 0; height: 1px; background-color: #000;">
                        <p style="color: #000;">
                            E-mail: owlslibrarysuporte@gmail.com <br>
                            Telefone: (11) 99965-2500
                        </p>
                    </footer>
                </body>
            `,
        };

        // Enviar o e-mail
        await sendMail(mailOptions);
        res.status(201).json(novoCliente);
    } catch (error) {
        res.status(400).json({ message: "Erro ao cadastrar cliente", error });
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
            clientes = await Cliente.find().sort({ createdAt: -1 }).limit(parseInt(limit));
        } else {
            clientes = await Cliente.find().sort({ createdAt: -1 }); // Caso contrário, retorna todos
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
                    { nome: { $regex: search, $options: 'i' } }, // Busca por nome
                    { sobrenome: { $regex: search, $options: 'i' } }, // Busca por sobrenome
                    { email: { $regex: search, $options: 'i' } }, // Busca por email
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

/* Rota para contar os emprestimos de cada cliente */
router.get('/api/emprestimos/count', async (req, res) => {
    const { clienteId } = req.query;

    if (!clienteId) {
        return res.status(400).json({ message: "Cliente ID é obrigatório" });
    }

    try {
        const count = await Emprestimo.countDocuments({ cliente: clienteId, devolvido: false });
        res.status(200).json({ count });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao contar empréstimos', error });
    }
});

/* Rota para contar a quantidade de livros emprestados */
router.get('/api/estatisticas/livros-emprestados', async (req, res) => {
    try {
        const emprestimos = await Emprestimo.find();
        const totalLivrosEmprestados = emprestimos.reduce((acc, emprestimo) => acc + emprestimo.livros.length, 0);

        res.status(200).json({ totalLivrosEmprestados });
    } catch (error) {
        console.error('Erro ao calcular livros emprestados:', error);
        res.status(500).json({ message: 'Erro ao calcular livros emprestados.', error });
    }
});

/* Rota para contar os livros cadastrados */
router.get('/api/livros/count', async (req, res) => {
    try {
        const count = await Livro.countDocuments();
        res.status(200).json({ count });
    } catch (error) {
        console.error('Erro ao contar livros:', error);
        res.status(500).json({ message: 'Erro ao contar livros', error });
    }
});
/* === fim página de clientes === */


/* === token === */
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
/* === fim do token === */

/* === Rota acervo === */
/* Rota para cadastrar livro */
router.post('/api/livros', async (req, res) => {
    let { nomeLivro, autor, genero, isbn, editora, dataLancamento, qtdCopias, image } = req.body;

    if (dataLancamento) {
        const partesData = dataLancamento.split('-'); // Divide o formato yyyy-MM-dd
        dataLancamento = new Date(partesData[0], partesData[1] - 1, partesData[2]); // Cria uma data no fuso local
    }

    genero = genero.trim();

    try {
        const novoLivro = new Livro({ nomeLivro, autor, genero, isbn, editora, dataLancamento, qtdCopias, image });
        await novoLivro.save();
        res.status(201).json(novoLivro);
    } catch (error) {
        res.status(400).json({ message: "Erro ao cadastrar livro", error });
    }
});


router.get("/api/livros", async (req, res) => {
    try {
        const livros = await Livro.find();
        const livrosFormatados = livros.map(livro => ({
            ...livro._doc,
            dataLancamento: livro.dataLancamento ? livro.dataLancamento.toISOString().split('T')[0] : null
        }));
        res.status(200).json(livrosFormatados);
    } catch (error) {
        console.error('Erro ao buscar livros:', error);
        res.status(500).json({ message: 'Erro ao buscar livros', error });
    }
});

// Rota para remover um livro
app.delete('/api/livros/:id', async (req, res) => {
    const livroId = req.params.id; // Obtém o ID do livro pela URL

    try {
        // Remover o livro do banco de dados
        const livroRemovido = await Livro.findByIdAndDelete(livroId);

        // Se o livro não for encontrado
        if (!livroRemovido) {
            return res.status(404).json({ message: 'Livro não encontrado' });
        }

        // Se a remoção for bem-sucedida
        res.status(200).json({ message: 'Livro removido com sucesso' });
    } catch (error) {
        console.error('Erro ao remover livro:', error);
        res.status(500).json({ message: 'Erro ao remover o livro', error: error.message });
    }
});

// Rota para remover um cliente
app.delete('/api/cliente/:id', async (req, res) => {
    const clienteId = req.params.id;

    try {
        // Remover o cliente do banco de dados
        const clienteRemovido = await Cliente.findByIdAndDelete(clienteId);

        // Se o livro não for encontrado
        if (!clienteRemovido) {
            return res.status(404).json({ message: 'cliente não encontrado' });
        }

        // Se a remoção for bem-sucedida
        res.status(200).json({ message: 'cliente removido com sucesso' });
    } catch (error) {
        console.error('Erro ao remover o cliente:', error);
        res.status(500).json({ message: 'Erro ao remover o cliente', error: error.message });
    }
});
/* === fim rota acervo === */


/* === rota de emprestimo === */
/* Rota para cadastrar empréstimo */
router.post('/api/emprestimos', async (req, res) => {
    const { cliente, livros, dataEmprestimo } = req.body;

    if (!cliente || !livros || !Array.isArray(livros) || livros.length === 0) {
        return res.status(400).json({ message: 'Cliente e pelo menos um livro são obrigatórios.' });
    }

    try {
        // Validação do cliente
        const clienteExistente = await Cliente.findById(cliente);
        if (!clienteExistente) {
            return res.status(404).json({ message: 'Cliente não encontrado.' });
        }

        // Validação dos livros
        const livrosUnicos = [...new Set(livros)];
        const livrosEncontrados = await Livro.find({ _id: { $in: livrosUnicos } });

        if (livrosEncontrados.length !== livrosUnicos.length) {
            return res.status(404).json({ message: 'Um ou mais livros não foram encontrados.' });
        }

        const livrosInvalidos = livrosEncontrados.filter(livro => !livro.isbn || !livro.editora);
        if (livrosInvalidos.length > 0) {
            return res.status(400).json({
                message: 'Alguns livros estão com informações incompletas.',
                livros: livrosInvalidos.map(livro => livro.nomeLivro),
            });
        }

        const indisponiveis = livrosEncontrados.filter(livro => livro.qtdCopias < 1);
        if (indisponiveis.length > 0) {
            return res.status(400).json({
                message: 'Alguns livros não estão disponíveis para empréstimo.',
                livros: indisponiveis.map(livro => livro.nomeLivro),
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

        // Configurar as opções de e-mail para o cliente
        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: clienteExistente.email,
            cc: 'owlslibrarysuporte@gmail.com',
            subject: 'Seu empréstimo realizado com sucesso!',
            html: `
                <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; color: #000;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #000; font-size: 24px; margin-bottom: 16px; text-align: left;">Olá, ${clienteExistente.nome}!</h1>
                        <hr style="margin: 10px 0; border: 0; height: 1px; background-color: #000;">
                        <p style="color: #000; line-height: 1.6; font-size: 16px; margin-bottom: 16px;">
                            Estamos felizes em informar que seu empréstimo foi registrado com sucesso. <br>
                            Agora você pode desfrutar de sua leitura e aproveitar ao máximo o conteúdo que escolheu. <br>
                            Não se esqueça de conferir o prazo para devolução e qualquer dúvida, estamos aqui para ajudar.
                        </p>
                        <p style="color: #000; font-size: 16px;">
                            Atenciosamente, <br>
                            Equipe Owl's Library.
                        </p>
                    </div>
                    <footer style="max-width: 600px; margin: 20px auto; text-align: left; font-size: 14px;">
                        <hr style="margin: 10px 0; border: 0; height: 1px; background-color: #000;">
                        <p style="color: #000;">
                            E-mail: owlslibrarysuporte@gmail.com <br>
                            Telefone: (11) 99965-2500
                        </p>
                    </footer>
                </body>
            `,

        };

        // Enviar o e-mail
        await sendMail(mailOptions);

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
            .sort({ dataEmprestimo: -1 });

        res.status(200).json(emprestimos);
    } catch (error) {
        console.error('Erro ao buscar empréstimos:', error);
        res.status(500).json({ message: 'Erro ao buscar empréstimos.', error });
    }
});

// Rota para devolução do empréstimo
router.put('/api/emprestimos/:id/devolucao', async (req, res) => {
    const emprestimoId = req.params.id;
    const { livros } = req.body;

    try {
        // Remover o empréstimo
        const emprestimo = await Emprestimo.findByIdAndDelete(emprestimoId);
        if (!emprestimo) {
            return res.status(404).json({ message: 'Empréstimo não encontrado' });
        }

        // Atualizar a quantidade de cópias dos livros devolvidos
        await Promise.all(livros.map(async (livroId) => {
            const livro = await Livro.findById(livroId);
            livro.qtdCopias += 1; // Devolvendo a cópia ao banco
            await livro.save();
        }));

        // Buscar o cliente relacionado ao empréstimo
        const cliente = await Cliente.findById(emprestimo.cliente);
        if (!cliente) {
            return res.status(404).json({ message: 'Cliente não encontrado' });
        }

        // Buscar o livro relacionado ao empréstimo
        const livro = await Livro.findById(emprestimo.livros);
        if (!livro) {
            return res.status(404).json({ message: 'Livro não encontrado' });
        }

        // Configurando a data de devolução no e-mail enviado
        const dataDevol = new Date().toLocaleDateString("pt-BR", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
        });

        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: cliente.email,
            cc: 'owlslibrarysuporte@gmail.com',
            subject: 'Devolução de Empréstimo Concluída com Sucesso!',
            html: `
                <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; color: #000;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #000; font-size: 24px; margin-bottom: 16px; text-align: left;">Olá, ${cliente.nome}!</h1>
                        <hr style="margin: 10px 0; border: 0; height: 1px; background-color: #000;">
                        <p style="color: #000; line-height: 1.6; font-size: 16px; margin-bottom: 16px;">
                            Agradecemos por devolver os livros que estavam em seu poder. <br>
                            Esperamos que a leitura tenha sido enriquecedora e prazerosa! <br><br>
                            Você realizou a devolução do livro "<strong>${livro.nomeLivro}</strong>", em: <strong>${dataDevol}</strong>. <br>
                            Sempre que precisar de novas obras para explorar, nossa biblioteca estará de portas abertas para você. Caso tenha qualquer dúvida, nossa equipe estará à disposição para ajudar.
                        </p>
                        <p style="color: #000; font-size: 16px;">Até a próxima leitura!</p>
                        <p style="color: #000;font-size: 16px;">
                            Atenciosamente, <br>
                            Equipe Owl's Library.
                        </p>
                    </div>
                    <footer style="max-width: 600px; margin: 20px auto; text-align: left; font-size: 14px;">
                        <hr style="margin: 10px 0; border: 0; height: 1px; background-color: #000;">
                        <p style="color: #000;">
                            E-mail: owlslibrarysuporte@gmail.com <br>
                            Telefone: (11) 99965-2500
                        </p>
                    </footer>
                </body>
            `,
        };

        // Enviar o e-mail
        await sendMail(mailOptions);

        res.status(200).json({ message: 'Devolução processada com sucesso e e-mail enviado.' });
    } catch (error) {
        console.error('Erro ao processar devolução:', error);
        res.status(500).json({ message: 'Erro ao processar devolução.', error: error.message });
    }
});
/* === fim da rota de emprestimo ===  */

/* Usando o router */
app.use(router);

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});

