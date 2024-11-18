const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: '127.0.0.1', // Intenta 'localhost' o '127.0.0.1'
  user: 'root',
  password: '',
  database: 'auth_system'
});

connection.connect((err) => {
  if (err) {
    return console.error('Error de conexión: ' + err.stack);
  }
  console.log('Conectado a MySQL en el host:', connection.config.host);
  connection.end();
});
