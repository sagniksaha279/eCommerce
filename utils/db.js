require("dotenv").config();
const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,

  // FreeDB does NOT provide a full SSL chain
  ssl: {
    rejectUnauthorized: false
  },

  waitForConnections: true,
  connectionLimit: 3,        // VERY IMPORTANT for FreeDB
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Simple query helper (used across app)
async function query(sql, params = []) {
  try {
    const [rows] = await pool.execute(sql, params);
    return rows;
  } catch (err) {
    console.error("DB QUERY ERROR:", err.sqlMessage || err.message);
    throw err;
  }
}

// Graceful shutdown (Render friendly)
process.on("SIGTERM", async () => {
  try {
    await pool.end();
    console.log("MySQL pool closed");
  } catch (e) {}
});

module.exports = {
  query,
  pool
};
