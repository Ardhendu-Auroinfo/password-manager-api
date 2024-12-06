const { Pool } = require('pg');
require('dotenv').config(); 

const db = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

(async () => {
  try {
    const client = await db.connect();
    console.log("Connected to PostgreSQL database!");
    client.release();
  } catch (err) {
    console.error("Error connecting to PostgreSQL:", err.message);
  }
})();

module.exports = db;
