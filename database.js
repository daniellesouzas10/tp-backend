const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./pdz.db', (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco:', err.message);
  } else {
    console.log('Banco conectado.');
  }
});

module.exports = db;