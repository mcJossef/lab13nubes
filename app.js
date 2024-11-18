const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const db = require('./db');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Redirigir la raíz (/) a la página de inicio de sesión
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Ruta de registro de usuarios
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  const hashedPassword = bcrypt.hashSync(password, 8);
  const tokenCode = Math.floor(100000 + Math.random() * 900000);

  const sql = 'INSERT INTO users (username, password, email, token_code) VALUES (?, ?, ?, ?)';
  db.query(sql, [username, hashedPassword, email, tokenCode], (err) => {
    if (err) {
      console.error("Error al registrar el usuario:", err);
      return res.status(500).json({ message: "Error al registrar el usuario en la base de datos" });
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de verificación',
      text: `Tu código de verificación es: ${tokenCode}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error al enviar el correo electrónico:", error);
        return res.status(500).json({ message: "Error al enviar el correo electrónico de verificación" });
      }
      console.log('Correo enviado: ' + info.response);
      res.json({ message: "Usuario registrado. Se ha enviado un código de verificación a tu correo electrónico." });
    });
  });
});

// Ruta para verificar el código de verificación de registro
app.post('/verify-code', (req, res) => {
  const { email, token_code } = req.body;

  if (!email || !token_code) {
    return res.status(400).json({ message: "El correo y el código de verificación son obligatorios" });
  }

  const sql = 'SELECT * FROM users WHERE email = ? AND token_code = ?';
  db.query(sql, [email, token_code], (err, results) => {
    if (err) {
      console.error("Error en la base de datos:", err);
      return res.status(500).json({ message: "Error en la base de datos" });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: "Código de verificación incorrecto" });
    }

    const token = jwt.sign({ email: results[0].email }, process.env.JWT_SECRET, { expiresIn: '30m' });
    res.json({ token, message: "Código de verificación correcto. Puedes iniciar sesión." });
  });
});

// Ruta de inicio de sesión
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Correo y contraseña son obligatorios" });
  }

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error("Error en la base de datos:", err);
      return res.status(500).json({ message: "Error en la base de datos" });
    }
    if (results.length === 0 || !bcrypt.compareSync(password, results[0].password)) {
      return res.status(401).json({ message: "Correo o contraseña incorrecta" });
    }

    // Generar el token de un solo uso
    const tokenCode = Math.floor(100000 + Math.random() * 900000);
    const updateTokenSql = 'UPDATE users SET token_code = ? WHERE email = ?';
    db.query(updateTokenSql, [tokenCode, email], (updateErr) => {
      if (updateErr) {
        console.error("Error al actualizar el token:", updateErr);
        return res.status(500).json({ message: "Error al generar el token" });
      }

      // Configurar las opciones de correo para enviar el token
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Código de acceso',
        text: `Tu código de acceso es: ${tokenCode}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Error al enviar el correo electrónico:", error);
          return res.status(500).json({ message: "Error al enviar el correo electrónico" });
        }
        console.log('Correo enviado: ' + info.response);
        res.json({ message: "Correo y contraseña correctos. Se ha enviado un código de acceso a tu correo electrónico." });
      });
    });
  });
});

// Ruta para verificar el token de acceso y completar el inicio de sesión
app.post('/verify-login-token', (req, res) => {
  const { email, token_code } = req.body;

  if (!email || !token_code) {
    return res.status(400).json({ message: "El correo y el token de acceso son obligatorios" });
  }

  const sql = 'SELECT * FROM users WHERE email = ? AND token_code = ?';
  db.query(sql, [email, token_code], (err, results) => {
    if (err) {
      console.error("Error en la base de datos:", err);
      return res.status(500).json({ message: "Error en la base de datos" });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: "Token de acceso incorrecto" });
    }

    const token = jwt.sign({ email: results[0].email }, process.env.JWT_SECRET, { expiresIn: '30m' });
    res.json({ token, message: "Token de acceso correcto. Acceso concedido." });
  });
});

// Ruta protegida para home.html
// Ruta protegida
app.get('/protected', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extrae el token
  
    if (!token) {
      return res.status(401).json({ message: "Token requerido" });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Token inválido" });
      }
      res.json({ message: `Bienvenido ${decoded.email}` });
    });
  });
  
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor en ejecución en http://localhost:${PORT}`));
