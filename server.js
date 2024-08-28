const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;
/* Porta do banco de dados */
const MONGO_URI = 'mongodb://localhost:27017/mydatabase';

app.use(cors());
app.use(bodyParser.json());


/* Conexão com o banco de dados */
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Conectado ao MongoDB'))
.catch(err => console.error('Erro ao conectar ao MongoDB', err));

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Inserir todos os campos' });
    }

    try {
        const user = await User.findOne({ email: email });

        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        if (user.password === password) {
            res.status(200).json({ message: 'Login bem-sucedido' });
        } else {
            res.status(400).json({ error: 'Email ou senha incorretos' });
        }
    } catch (error) {
        console.error('Erro ao autenticar usuário:', error);
        res.status(500).json({ error: 'Erro ao autenticar usuário' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
