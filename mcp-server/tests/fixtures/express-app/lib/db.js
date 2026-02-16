const mysql = require('mysql');
const connection = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

function getUserById(id) {
  const query = "SELECT * FROM users WHERE id = " + id;
  return connection.query(query);
}

function searchUsers(term) {
  const query = "SELECT * FROM users WHERE name LIKE '%" + term + "%'";
  return connection.query(query);
}

module.exports = { getUserById, searchUsers };
