const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const PGHOST = process.env.PGHOST || 'postgres-service';
const PGUSER = process.env.PGUSER || 'postgres';
const PGPASSWORD = process.env.PGPASSWORD || 'postgrespw';
const PGDATABASE = process.env.PGDATABASE || 'demo';
const PGPORT = process.env.PGPORT || 5432;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const SALT_ROUNDS = 10;

const pool = new Pool({ host: PGHOST, user: PGUSER, password: PGPASSWORD, database: PGDATABASE, port: PGPORT });

async function initDb(){
  const client = await pool.connect();
  try{
    // existing items table
    await client.query(`CREATE TABLE IF NOT EXISTS items (id SERIAL PRIMARY KEY, text TEXT NOT NULL);`);
    const res = await client.query('SELECT count(*) FROM items');
    if(res.rows[0].count === '0'){
      await client.query("INSERT INTO items(text) VALUES('Bienvenidos a Kubernetes demo');");
    }

    // students and courses
    await client.query(`
      CREATE TABLE IF NOT EXISTS students (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS attendance (
        id SERIAL PRIMARY KEY,
        student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
        date DATE NOT NULL,
        present BOOLEAN NOT NULL,
        recorded_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS attendance_unique_idx
      ON attendance (student_id, course_id, date);
    `);

    // users table for auth + optional link to students table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin','teacher','student')),
        student_id INTEGER NULL REFERENCES students(id) ON DELETE SET NULL
      );
    `);

    // Seed minimal data if none
    const { rows: stuCount } = await client.query('SELECT count(*) FROM students');
    if (stuCount[0].count === '0') {
      await client.query("INSERT INTO students(name) VALUES ('Alumno Demo 1'), ('Alumno Demo 2'), ('Alumno Demo 3');");
    }
    const { rows: courseCount } = await client.query('SELECT count(*) FROM courses');
    if (courseCount[0].count === '0') {
      await client.query("INSERT INTO courses(name) VALUES ('Matemáticas'), ('Historia');");
    }

    const { rows: userCount } = await client.query('SELECT count(*) FROM users');
    if (userCount[0].count === '0') {
      // create admin, teacher and a student user (passwords for testing)
      const adminPassHash = await bcrypt.hash('adminpass', SALT_ROUNDS);
      const teacherPassHash = await bcrypt.hash('teacherpass', SALT_ROUNDS);
      const studentPassHash = await bcrypt.hash('studentpass', SALT_ROUNDS);

      // create student record to link to student user (use first student id)
      const { rows: students } = await client.query('SELECT id FROM students ORDER BY id LIMIT 1');
      const firstStudentId = students[0].id;

      await client.query(
        `INSERT INTO users(username,password_hash,role,student_id) VALUES
          ('admin','${adminPassHash}','admin', NULL),
          ('prof1','${teacherPassHash}','teacher', NULL),
          ('student1','${studentPassHash}','student', ${firstStudentId})
        `
      );
      console.log('Seeded users: admin/adminpass, prof1/teacherpass, student1/studentpass');
    }

  } finally { client.release(); }
}

/* -----------------------
   Auth helpers and middleware
   ----------------------- */

function signToken(user) {
  // embed minimal info: user id and role (and student_id if any)
  return jwt.sign({ uid: user.id, role: user.role, student_id: user.student_id || null }, JWT_SECRET, { expiresIn: '8h' });
}

async function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'missing token' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { uid, role, student_id }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

function authorize(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'not authenticated' });
    if (allowedRoles.length === 0) return next(); // allow any authenticated
    if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

/* -----------------------
   Public auth endpoints
   ----------------------- */

// Login: { username, password } -> { token, role, uid, student_id }
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (rows.length === 0) return res.status(401).json({ error: 'invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    const token = signToken(user);
    res.json({ token, role: user.role, uid: user.id, student_id: user.student_id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Register/create user (admin only). Body example:
// { username, password, role: 'teacher'|'admin'|'student', student_name: 'Nombre' }
// If role='student' and student_name provided, creates student and links.
app.post('/api/auth/register', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const { username, password, role, student_name } = req.body;
    if (!username || !password || !role) return res.status(400).json({ error: 'username,password,role required' });
    if (!['admin','teacher','student'].includes(role)) return res.status(400).json({ error: 'invalid role' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      let student_id = null;
      if (role === 'student') {
        if (!student_name) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'student_name required for role student' }); }
        const { rows: srows } = await client.query('INSERT INTO students(name) VALUES($1) RETURNING id', [student_name]);
        student_id = srows[0].id;
      }
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      const { rows: ur } = await client.query('INSERT INTO users(username,password_hash,role,student_id) VALUES($1,$2,$3,$4) RETURNING id,username,role,student_id', [username, hash, role, student_id]);
      await client.query('COMMIT');
      res.json(ur[0]);
    } catch (err) {
      await client.query('ROLLBACK');
      if (err.code === '23505') return res.status(400).json({ error: 'username exists' });
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

/* -----------------------
   Existing items endpoints (public)
   ----------------------- */
app.get('/api/items', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM items ORDER BY id DESC');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/items', async (req, res) => {
  try {
    const { text } = req.body;
    if(!text) return res.status(400).json({ error: 'text required' });
    const { rows } = await pool.query('INSERT INTO items(text) VALUES($1) RETURNING *', [text]);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

/* -----------------------
   Students and Courses
   - create: admin/teacher
   - list: admin/teacher (all), student sees only their own info (if linked)
   ----------------------- */

// Get students (protected)
app.get('/api/students', authenticate, async (req, res) => {
  try {
    if (req.user.role === 'student') {
      if (!req.user.student_id) return res.status(403).json({ error: 'no student profile' });
      const { rows } = await pool.query('SELECT * FROM students WHERE id = $1', [req.user.student_id]);
      return res.json(rows);
    } else {
      const { rows } = await pool.query('SELECT * FROM students ORDER BY id');
      return res.json(rows);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

// Create student
app.post('/api/students', authenticate, authorize(['admin','teacher']), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const { rows } = await pool.query('INSERT INTO students(name) VALUES($1) RETURNING *', [name]);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

// Courses
app.get('/api/courses', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM courses ORDER BY id');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/courses', authenticate, authorize(['admin','teacher']), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const { rows } = await pool.query('INSERT INTO courses(name) VALUES($1) RETURNING *', [name]);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

/* -----------------------
   Attendance endpoints (protected)
   - POST /api/attendance : admin/teacher (record batch)
   - GET /api/attendance  : admin/teacher (query by course_id & date)
   - GET /api/attendance/self : student (view own record by date)
   ----------------------- */

// Record attendance (batch). body: { course_id, date: 'YYYY-MM-DD', records: [{ student_id, present }] }
app.post('/api/attendance', authenticate, authorize(['admin','teacher']), async (req, res) => {
  const client = await pool.connect();
  try {
    const { course_id, date, records } = req.body;
    if (!course_id || !date || !Array.isArray(records)) {
      return res.status(400).json({ error: 'course_id, date and records[] required' });
    }

    await client.query('BEGIN');
    for (const r of records) {
      if (typeof r.student_id !== 'number' || typeof r.present !== 'boolean') {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'each record must have student_id (number) and present (boolean)' });
      }
      await client.query(`
        INSERT INTO attendance(student_id, course_id, date, present)
        VALUES($1, $2, $3, $4)
        ON CONFLICT (student_id, course_id, date)
        DO UPDATE SET present = EXCLUDED.present, recorded_at = now()
      `, [r.student_id, course_id, date, r.present]);
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
  }
});

// Get attendance by course and date: admin/teacher
app.get('/api/attendance', authenticate, authorize(['admin','teacher']), async (req, res) => {
  try {
    const { course_id, date } = req.query;
    if (!course_id || !date) return res.status(400).json({ error: 'course_id and date required' });

    const { rows } = await pool.query(`
      SELECT a.*, s.name as student_name
      FROM attendance a
      JOIN students s ON s.id = a.student_id
      WHERE a.course_id = $1 AND a.date = $2
      ORDER BY s.id
    `, [course_id, date]);

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

// Student: get own attendance for a date (protected)
app.get('/api/attendance/self', authenticate, authorize(['student']), async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: 'date required' });
    if (!req.user.student_id) return res.status(400).json({ error: 'student profile not linked' });

    const { rows } = await pool.query(`
      SELECT a.*, c.name as course_name
      FROM attendance a
      JOIN courses c ON c.id = a.course_id
      WHERE a.student_id = $1 AND a.date = $2
    `, [req.user.student_id, date]);

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/healthz', (req,res)=> res.send('ok'));

const PORT = process.env.PORT || 3000;

initDb().then(()=>{
  app.listen(PORT, () => console.log(`Backend listening on ${PORT}`));
}).catch(err => { console.error('DB init failed', err); process.exit(1); });