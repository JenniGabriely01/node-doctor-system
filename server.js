const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');  // Certifique-se de importar o pacote cors
const app = express();

const PORT = 3000;

// Configurando o CORS
app.use(cors());

/* Dados usuarios */
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const Usuarios = mongoose.model('User', userSchema);

/* Conexão com o MongoDB (Porta padrão) */
mongoose.connect('mongodb://localhost:27017/library-system', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Failed to connect to MongoDB', err));

app.get('/testeApi', (req, res) => {
  res.json([{'titulo': 'Testando conexão front com back'}]);
});

/* app.get('/', (req, res) => {
  Rota do login
}); */

app.listen(PORT, () => {
  console.log(`o Servidor iniciou na porta ${PORT} `);
});
