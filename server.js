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
const REFRESH_TOKEN = '1//04o4iZ89yvdKNCgYIARAAGAQSNwF-L9Ir0jBazI68ZPN3vORZOsd3bk7MAhsVYvd8GyBN30jVHVGTrgUI8daXL7VKZNt9BxxQBX0';

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

/* --------- rotas para o dashboard ---------- */

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

/* Rota para cadastrar cliente */
router.post('/api/clientes', async (req, res) => {
    const { nome, sobrenome, email, telefone } = req.body;
    try {
        const novoCliente = new Cliente({ nome, sobrenome, email, telefone });
        await novoCliente.save();

        // Configurar as opções de e-mail com os dados do cliente
        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: email, // Enviar o e-mail para o cliente recém-cadastrado
            subject: 'Bem-vindo à nossa plataforma!',
            text: `Olá ${nome}, obrigado por se cadastrar na nossa plataforma!`,
            html: `
                <body style="overflow-x: hidden; padding: 0; font-family: Arial, sans-serif; color: #333;">
                    <div>
                        <h1 style="color: #333; font-size: 2.5vw; margin-bottom: 1vw;">Bem-vindo, ${nome}!</h1>
                            <hr style="margin: 0; width: 30vw; height: 0.05vw; background-color: #333;">
                        <p style="line-height: 2vw; margin-bottom: 2vw; font-size: 1.25vw;">
                            Estamos felizes em informar que seu cadastro foi realizado com sucesso. <br>
                            Agora você faz parte de nossa comunidade e poderá usufruir de nossos <br>
                            serviços, como empréstimo de livros e acesso a novidades da biblioteca.
                        </p>
                        <p style="font-size: 1.25vw; margin-bottom: 2vw;">Em caso de dúvidas, estamos à disposição. Boas leituras!</p>
                            <p style="font-size: 1.25vw;">
                                Atenciosamente, <br>
                                Equipe Owl's Library.
                            </p>
                    </div>
                    <footer>
                        <div>
                            <hr style="margin: 0; width: 30vw; height: 0.05vw; background-color: #333;">
                            <p style="font-size: 1.25vw;">
                                E-mail: owlslibrarysuporte@gmail.com <br>
                                Telefone: (11) 99965-2500
                            </p>
                        </div>
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

/* Rota para cadastrar livro */
router.post('/api/livros', async (req, res) => {
    let { nomeLivro, autor, genero, dataLancamento, qtdCopias, image } = req.body;

    // Remove espaços extras antes e depois do gênero
    genero = genero.trim();

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
    try {
        const livros = await Livro.find();
        res.status(200).json(livros);
    } catch (error) {
        console.error('Erro ao buscar livros:', error); // Log do erro
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

        // Configurar as opções de e-mail para o cliente
        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: clienteExistente.email, // Enviar o e-mail para o cliente
            subject: 'Seu empréstimo realizado com sucesso!',
            html: `
                <body style="overflow-x: hidden; padding: 0; font-family: Arial, sans-serif; color: #333;">
                    <div>
                        <h1 style="color: #333; font-size: 2.5vw; margin-bottom: 1vw;">Olá, ${clienteExistente.nome}!</h1>
                            <hr style="margin: 0; width: 30vw; height: 0.05vw; background-color: #333;">
                        <p style="line-height: 2vw; margin-bottom: 2vw; font-size: 1.25vw;">
                            Estamos felizes em informar que seu empréstimo foi registrado com sucesso. <br>
                            Agora você pode desfrutar de sua leitura e aproveitar ao máximo o conteúdo que escolheu. <br>
                            Não se esqueça de conferir o prazo para devolução e qualquer dúvida, estamos aqui para ajudar.
                            <br><br>
                            Atenciosamente, <br>
                            Equipe Owl's Library.
                        </p>
                    </div>
                    <footer>
                        <div>
                            <hr style="margin: 0; width: 30vw; height: 0.05vw; background-color: #333;">
                            <p style="font-size: 1.25vw; color: #333; text-decoration: none;">
                                E-mail: owlslibrarysuporte@gmail.com <br>
                                Telefone: (11) 99965-2500
                            </p>
                        </div>
                    </footer>
                </body>  
            `
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
            .sort({ data: -1 });
        res.status(200).json(emprestimos);
    } catch (error) {
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

        // Configurar as opções de e-mail com os dados do cliente para a devolução
        const mailOptions = {
            from: 'owlslibrarysuporte@gmail.com',
            to: cliente.email,
            subject: 'Devolução de Empréstimo Concluída com Sucesso!',
            html: `
                <body style="overflow-x: hidden; padding: 0; font-family: Arial, sans-serif; color: #333;">
                    <div>
                        <h1 style="color: #333; font-size: 2.5vw; margin-bottom: 1vw;">Olá, ${cliente.nome}!</h1>
                            <hr style="margin: 0; width: 30vw; height: 0.05vw; background-color: #333;">
                        <p style="line-height: 2vw; margin-bottom: 2vw; font-size: 1.25vw;">
                            Agradecemos por devolver os livros que estavam em seu poder. <br>
                            Esperamos que a leitura tenha sido enriquecedora e prazerosa! <br><br>

                            Sempre que precisar de novas obras para explorar, nossa biblioteca <br>
                            estará de portas abertas para você. Caso tenha qualquer dúvida, <br>
                            nossa equipe estará à disposição para ajudar.
                        </p>
                        <p style="font-size: 1.25vw; margin-bottom: 2vw;">Até a próxima leitura!</p>
                            <p style="font-size: 1.25vw;">
                                Atenciosamente, <br>
                                Equipe Owl's Library.
                            </p>
                    </div>
                    <footer>
                        <div>
                            <hr style="margin: 0; width: 30vw; height: 0.05vw; background-color: #333;">
                            <p style="font-size: 1.25vw;">
                                E-mail: owlslibrarysuporte@gmail.com <br>
                                Telefone: (11) 99965-2500
                            </p>
                        </div>
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


/* Usando o router */
app.use(router);

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});

