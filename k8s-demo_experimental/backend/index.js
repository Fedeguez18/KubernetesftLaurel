const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PGHOST = process.env.PGHOST || 'postgres';
const PGUSER = process.env.PGUSER || 'postgres';
const PGPASSWORD = process.env.PGPASSWORD || 'postgrespw';
const PGDATABASE = process.env.PGDATABASE || 'demo';
const PGPORT = process.env.PGPORT || 5432;

const pool = new Pool({ host: PGHOST, user: PGUSER, password: PGPASSWORD, database: PGDATABASE, port: PGPORT });

async function initDb(){
  const client = await pool.connect();
  try{
    await client.query(`CREATE TABLE IF NOT EXISTS items (id SERIAL PRIMARY KEY, text TEXT NOT NULL);`);
    const res = await client.query('SELECT count(*) FROM items');
    if(res.rows[0].count === '0'){
      await client.query("INSERT INTO items(text) VALUES('Bienvenidos a Kubernetes demo');");
    }
  } finally { client.release(); }
}

app.get('/api/items', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM items ORDER BY id DESC');
  res.json(rows);
});

app.post('/api/items', async (req, res) => {
  const { text } = req.body;
  if(!text) return res.status(400).json({ error: 'text required' });
  const { rows } = await pool.query('INSERT INTO items(text) VALUES($1) RETURNING *', [text]);
  res.json(rows[0]);
});

app.get('/healthz', (req,res)=> res.send('ok'));

const PORT = process.env.PORT || 3000;

initDb().then(()=>{
  app.listen(PORT, () => console.log(`Backend listening on ${PORT}`));
}).catch(err => { console.error('DB init failed', err); process.exit(1); });
