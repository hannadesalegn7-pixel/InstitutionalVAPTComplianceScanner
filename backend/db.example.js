const { Pool } = require("pg");

const pool = new Pool({
  host: "localhost",
  port: 5432,
  user: "postgres",
  password: process.env.DB_PASSWORD || "yourpassword",
  database: "vapt_scanner",
});

module.exports = pool;