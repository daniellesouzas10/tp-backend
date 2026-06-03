require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

const db = require('./database');

const app = express();

app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

/* =========================================================
   UPLOADS
========================================================= */

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const uploadDir = path.join(__dirname, 'uploads', 'mentoria');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },

  filename(req, file, cb) {
    const safeName = file.originalname
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-zA-Z0-9.\-_]/g, '_');

    cb(null, `${Date.now()}-${safeName}`);
  }
});

const uploadMentoria = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const allowed = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Envie apenas PDF, DOC ou DOCX.'));
    }

    cb(null, true);
  }
});

function uploadSingle(fieldName) {
  return function (req, res, next) {
    uploadMentoria.single(fieldName)(req, res, function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }
      next();
    });
  };
}

/* =========================================================
   INIT DB
========================================================= */

const schema = fs.readFileSync('./schema.sql', 'utf8');
db.exec(schema);

db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN address TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'`, () => {});
db.run(`ALTER TABLE users ADD COLUMN created_at DATETIME`, () => {});

db.run(`UPDATE users SET status = 'active' WHERE status IS NULL OR status = ''`, () => {});
db.run(`UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL OR created_at = ''`, () => {});

db.run(`ALTER TABLE student_products ADD COLUMN curso_id INTEGER`, () => {});
db.run(`ALTER TABLE student_products ADD COLUMN imersao_config TEXT`, () => {});
db.run(`ALTER TABLE student_products ADD COLUMN mentoria_config TEXT`, () => {});
db.run(`ALTER TABLE student_products ADD COLUMN imersao_access_level INTEGER`, () => {});
db.run(`ALTER TABLE student_products ADD COLUMN imersao_day_1_release TEXT`, () => {});
db.run(`ALTER TABLE student_products ADD COLUMN imersao_day_2_release TEXT`, () => {});
db.run(`ALTER TABLE student_products ADD COLUMN event_datetime TEXT`, () => {});

db.run(`
  CREATE TABLE IF NOT EXISTS student_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_type TEXT NOT NULL,
    product_name TEXT NOT NULL,
    release_datetime TEXT NOT NULL,
    main_url TEXT,
    material_url TEXT,
    bonus_url TEXT,
    notes TEXT,
    access_status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS mentoria_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    week_number INTEGER NOT NULL,
    task_title TEXT,
    task_file_url TEXT,
    task_original_name TEXT,
    task_uploaded_at DATETIME,
    report_file_url TEXT,
    report_original_name TEXT,
    report_uploaded_at DATETIME,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);


db.run(`
  CREATE TABLE IF NOT EXISTS extra_materials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    target TEXT DEFAULT 'draft',
    product_types TEXT,
    course_ids TEXT,
    course_refs TEXT,
    student_ids TEXT,
    student_refs TEXT,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_id TEXT,
    tipo TEXT NOT NULL,
    nome TEXT NOT NULL,
    apelido TEXT,
    dataInicio TEXT,
    hora TEXT,
    sessoes TEXT,
    status TEXT DEFAULT 'ativo',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

/* =========================================================
   AUTH
========================================================= */

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: 'Token não enviado.' });
  }

  const token = header.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido.' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso restrito ao administrador.' });
  }

  next();
}

/* =========================================================
   AUTH ROUTES
========================================================= */

app.post('/auth/register-admin', async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')`,
    [name, email, hash],
    function (err) {
      if (err) {
        return res.status(400).json({ error: 'Erro ao criar admin.', details: err.message });
      }

      res.json({ id: this.lastID, name, email, role: 'admin' });
    }
  );
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Login inválido.' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: 'Senha inválida.' });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Usuário bloqueado.' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  });
});

/* =========================================================
   ADMIN — ALUNOS
========================================================= */

app.post('/admin/students', auth, adminOnly, async (req, res) => {
  const { name, email, password, plan_id } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'student')`,
    [name, email, hash],
    function (err) {
      if (err) {
        return res.status(400).json({ error: 'Erro ao criar aluno.', details: err.message });
      }

      const userId = this.lastID;

      if (plan_id) {
        db.run(`INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)`, [userId, plan_id]);
      }

      res.json({ id: userId, name, email, role: 'student', plan_id });
    }
  );
});

app.get('/admin/students', auth, adminOnly, (req, res) => {
  db.all(
    `
    SELECT 
      users.id,
      users.name,
      users.email,
      COALESCE(users.status, 'active') AS status,
      COALESCE(plans.name, '—') AS plan
    FROM users
    LEFT JOIN user_plans ON user_plans.user_id = users.id
    LEFT JOIN plans ON plans.id = user_plans.plan_id
    WHERE users.role = 'student'
    ORDER BY users.id DESC
    `,
    [],
    (err, rows) => {
      if (err) {
        console.error('ERRO /admin/students:', err.message);
        return res.status(400).json({ error: err.message });
      }

      res.json(rows || []);
    }
  );
});

app.patch('/admin/students/:id/status', auth, adminOnly, (req, res) => {
  const { status } = req.body;

  db.run(`UPDATE users SET status = ? WHERE id = ?`, [status, req.params.id], function (err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true });
  });
});

app.patch('/admin/students/:id/plan', auth, adminOnly, (req, res) => {
  const { plan_id } = req.body;

  db.run(`DELETE FROM user_plans WHERE user_id = ?`, [req.params.id], () => {
    db.run(
      `INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)`,
      [req.params.id, plan_id],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ success: true });
      }
    );
  });
});

/* =========================================================
   ADMIN — PLANOS
========================================================= */

app.post('/admin/plans', auth, adminOnly, (req, res) => {
  const { name, description } = req.body;

  db.run(`INSERT INTO plans (name, description) VALUES (?, ?)`, [name, description], function (err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ id: this.lastID, name, description });
  });
});

app.get('/admin/plans', auth, adminOnly, (req, res) => {
  db.all(`SELECT * FROM plans ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

/* =========================================================
   ADMIN — MÓDULOS / AULAS / ACESSO
========================================================= */

app.post('/admin/modules', auth, adminOnly, (req, res) => {
  const { title, description, order_number, status } = req.body;

  db.run(
    `INSERT INTO modules (title, description, order_number, status) VALUES (?, ?, ?, ?)`,
    [title, description, order_number, status || 'published'],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, title, description });
    }
  );
});

app.get('/admin/modules', auth, adminOnly, (req, res) => {
  db.all(`SELECT * FROM modules ORDER BY order_number ASC`, [], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/admin/lessons', auth, adminOnly, (req, res) => {
  const { module_id, title, video_url, description, duration, order_number, status } = req.body;

  db.run(
    `
    INSERT INTO lessons 
    (module_id, title, video_url, description, duration, order_number, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [module_id, title, video_url, description, duration, order_number, status || 'published'],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, title });
    }
  );
});

app.get('/admin/lessons', auth, adminOnly, (req, res) => {
  db.all(
    `
    SELECT lessons.*, modules.title AS module_title
    FROM lessons
    LEFT JOIN modules ON modules.id = lessons.module_id
    ORDER BY modules.order_number ASC, lessons.order_number ASC
    `,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/admin/access', auth, adminOnly, (req, res) => {
  const { plan_id, module_id, lesson_id } = req.body;

  db.run(
    `INSERT INTO plan_access (plan_id, module_id, lesson_id) VALUES (?, ?, ?)`,
    [plan_id, module_id || null, lesson_id || null],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    }
  );
});

/* =========================================================
   ADMIN — AVISOS
========================================================= */

app.post('/admin/notices', auth, adminOnly, (req, res) => {
  const { title, message, target, type } = req.body;

  db.run(
    `INSERT INTO notices (title, message, target, type) VALUES (?, ?, ?, ?)`,
    [title, message, target || 'all', type || 'info'],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, title, message });
    }
  );
});

app.get('/admin/notices', auth, adminOnly, (req, res) => {
  db.all(`SELECT * FROM notices ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

/* =========================================================
   ADMIN — PRODUTOS / LIBERAÇÕES
========================================================= */

app.post('/admin/product-release', auth, adminOnly, (req, res) => {
  const {
    user_id,
    product_type,
    product_name,
    release_datetime,
    main_url,
    material_url,
    bonus_url,
    notes,
    imersao_config,
    mentoria_config,
    imersao_access_level,
    imersao_day_1_release,
    imersao_day_2_release,
    event_datetime
  } = req.body;

  if (!user_id || !product_type || !product_name || !release_datetime) {
    return res.status(400).json({
      error: 'Informe aluno, produto, nome do produto e data/hora de liberação.'
    });
  }

  db.run(
    `
    INSERT INTO student_products
    (user_id, product_type, product_name, release_datetime,
     main_url, material_url, bonus_url, notes, access_status,
     imersao_config, mentoria_config,
     imersao_access_level, imersao_day_1_release, imersao_day_2_release,
     curso_id, event_datetime)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      user_id,
      product_type,
      product_name,
      release_datetime,
      main_url || null,
      material_url || null,
      bonus_url || null,
      notes || null,
      imersao_config ? JSON.stringify(imersao_config) : null,
      mentoria_config ? JSON.stringify(mentoria_config) : null,
      imersao_access_level ?? null,
      imersao_day_1_release || null,
      imersao_day_2_release || null,
      req.body.curso_id || null,
      event_datetime || null
    ],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ success: true, id: this.lastID, message: 'Produto liberado para o aluno.' });
    }
  );
});

app.get('/admin/product-releases', auth, adminOnly, (req, res) => {
  db.all(
    `
    SELECT sp.*, u.name AS student_name, u.email AS student_email
    FROM student_products sp
    LEFT JOIN users u ON u.id = sp.user_id
    ORDER BY sp.created_at DESC
    `,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.patch('/admin/product-release/:id', auth, adminOnly, (req, res) => {
  const { status, main_url, material_url, notes, imersao_config_patch, mentoria_sessoes_patch } = req.body;
  const { id } = req.params;

  db.get(`SELECT * FROM student_products WHERE id = ?`, [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Liberação não encontrada.' });

    let newImersaoConfig = row.imersao_config ? JSON.parse(row.imersao_config) : null;
    let newMentoriaConfig = row.mentoria_config ? JSON.parse(row.mentoria_config) : null;

    if (imersao_config_patch && newImersaoConfig) {
      const { link1, mat1, link2, mat2 } = imersao_config_patch;

      if (!newImersaoConfig.day_1) newImersaoConfig.day_1 = {};
      if (!newImersaoConfig.day_2) newImersaoConfig.day_2 = {};

      if (link1 !== undefined) newImersaoConfig.day_1.link = link1 || null;
      if (mat1 !== undefined) newImersaoConfig.day_1.material = mat1 || null;
      if (link2 !== undefined) newImersaoConfig.day_2.link = link2 || null;
      if (mat2 !== undefined) newImersaoConfig.day_2.material = mat2 || null;
    }

    if (mentoria_sessoes_patch && Array.isArray(newMentoriaConfig)) {
  newMentoriaConfig = newMentoriaConfig.map((s, i) => ({
    ...s,
    linkPrincipal: mentoria_sessoes_patch[i]?.linkPrincipal ?? s.linkPrincipal,
    material:      mentoria_sessoes_patch[i]?.material      ?? s.material,
    bonus:         mentoria_sessoes_patch[i]?.bonus         ?? s.bonus,
    data:          mentoria_sessoes_patch[i]?.data          ?? s.data,
    hora:          mentoria_sessoes_patch[i]?.hora          ?? s.hora
  }));
}

    db.run(
      `
      UPDATE student_products
      SET main_url = ?, material_url = ?, notes = ?, access_status = ?,
          imersao_config = ?, mentoria_config = ?
      WHERE id = ?
      `,
      [
        main_url !== undefined ? main_url || null : row.main_url,
        material_url !== undefined ? material_url || null : row.material_url,
        notes !== undefined ? notes || null : row.notes,
        status === 'concluido' ? 'concluido' : 'active',
        newImersaoConfig ? JSON.stringify(newImersaoConfig) : row.imersao_config,
        newMentoriaConfig ? JSON.stringify(newMentoriaConfig) : row.mentoria_config,
        id
      ],
      function (err2) {
        if (err2) return res.status(400).json({ error: err2.message });
        res.json({ success: true });
      }
    );
  });
});

/* =========================================================
   ALUNO — MEUS DADOS / PRODUTOS
========================================================= */

app.get('/me', auth, (req, res) => {
  db.get(
    `
    SELECT 
      users.id,
      users.name,
      users.email,
      users.role,
      users.phone,
      users.address,
      plans.name AS plan
    FROM users
    LEFT JOIN user_plans ON user_plans.user_id = users.id
    LEFT JOIN plans ON plans.id = user_plans.plan_id
    WHERE users.id = ?
    `,
    [req.user.id],
    (err, row) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(row);
    }
  );
});

app.patch('/me', auth, async (req, res) => {
  const { name, phone, address, password } = req.body;

  if (!name || name.trim().length < 2) {
    return res.status(400).json({ error: 'Nome inválido.' });
  }

  if (password && password.length < 6) {
    return res.status(400).json({ error: 'A senha deve ter pelo menos 6 caracteres.' });
  }

  if (password) {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      `UPDATE users SET name = ?, phone = ?, address = ?, password_hash = ? WHERE id = ?`,
      [name, phone || null, address || null, hash, req.user.id],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ success: true });
      }
    );
  } else {
    db.run(
      `UPDATE users SET name = ?, phone = ?, address = ? WHERE id = ?`,
      [name, phone || null, address || null, req.user.id],
      function (err) {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ success: true });
      }
    );
  }
});

app.get('/student/products', auth, (req, res) => {
  db.all(
    `
    SELECT *
    FROM student_products
    WHERE user_id = ?
    AND access_status = 'active'
    ORDER BY release_datetime ASC
    `,
    [req.user.id],
    (err, products) => {
      if (err) return res.status(400).json({ error: err.message });

      const now = new Date();

      const formatted = products.map(product => {
        const releaseDate = new Date(product.release_datetime);

        return {
          ...product,
          released: now >= releaseDate,
          event_datetime: product.event_datetime || null,
          imersao_config: product.imersao_config ? JSON.parse(product.imersao_config) : null,
          mentoria_config: product.mentoria_config ? JSON.parse(product.mentoria_config) : null
        };
      });

      res.json(formatted);
    }
  );
});

app.get('/student/workshop', auth, (req, res) => {
  db.get(
    `
    SELECT *
    FROM student_products
    WHERE user_id = ?
    AND product_type = 'workshop'
    AND access_status = 'active'
    ORDER BY release_datetime ASC
    LIMIT 1
    `,
    [req.user.id],
    (err, product) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!product) return res.json(null);

      const now = new Date();
      const releaseDate = new Date(product.release_datetime);
      const released = now >= releaseDate;

      res.json({
        id: product.id,
        title: product.product_name,
        description: product.notes || 'Um encontro ao vivo de 2 horas para diagnosticar os principais gargalos da carreira.',
        event_datetime: product.release_datetime,
        live_url: product.main_url,
        material_url: released ? product.material_url : null,
        bonus_url: released ? product.bonus_url : null,
        released,
        materials: released
          ? [
              product.material_url ? { title: 'Material do Aluno', file_url: product.material_url } : null,
              product.bonus_url ? { title: 'Autodiagnóstico da Carreira', file_url: product.bonus_url } : null
            ].filter(Boolean)
          : []
      });
    }
  );
});

app.get('/student/content', auth, (req, res) => {
  db.all(
    `
    SELECT DISTINCT
      modules.id AS module_id,
      modules.title AS module_title,
      modules.description AS module_description,
      lessons.id AS lesson_id,
      lessons.title AS lesson_title,
      lessons.video_url,
      lessons.duration
    FROM users
    JOIN user_plans ON user_plans.user_id = users.id
    JOIN plan_access ON plan_access.plan_id = user_plans.plan_id
    LEFT JOIN modules ON modules.id = plan_access.module_id
    LEFT JOIN lessons ON lessons.module_id = modules.id OR lessons.id = plan_access.lesson_id
    WHERE users.id = ?
    AND modules.status = 'published'
    AND lessons.status = 'published'
    ORDER BY modules.order_number ASC, lessons.order_number ASC
    `,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

/* =========================================================
   ALUNO — AVISOS / PROGRESSO
========================================================= */

app.get('/student/notices', auth, (req, res) => {
  const userTarget = `user_${req.user.id}`;

  db.all(
    `
    SELECT *
    FROM notices
    WHERE target = 'all'
    OR target = ?
    ORDER BY created_at DESC
    LIMIT 20
    `,
    [userTarget],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/student/notifications', auth, (req, res) => {
  const userTarget = `user_${req.user.id}`;

  db.all(
    `
    SELECT *
    FROM notices
    WHERE target = 'all'
    OR target = ?
    ORDER BY created_at DESC
    LIMIT 20
    `,
    [userTarget],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows.map(r => ({ ...r, read: false })));
    }
  );
});

app.post('/student/progress', auth, (req, res) => {
  const { lesson_id, completed, progress_percent } = req.body;

  db.run(
    `
    INSERT INTO progress (user_id, lesson_id, completed, progress_percent)
    VALUES (?, ?, ?, ?)
    `,
    [req.user.id, lesson_id, completed ? 1 : 0, progress_percent || 0],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.get('/student/progress', auth, (req, res) => {
  db.all(`SELECT * FROM progress WHERE user_id = ?`, [req.user.id], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

/* =========================================================
   MENTORIA — TAREFAS E RELATÓRIOS
========================================================= */

app.get('/student/mentoria-tasks', auth, (req, res) => {
  db.all(
    `
    SELECT *
    FROM mentoria_tasks
    WHERE user_id = ?
    ORDER BY week_number ASC
    `,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/student/mentoria-tasks/upload', auth, uploadSingle('task_file'), (req, res) => {
  const { product_id, week_number, task_title } = req.body;

  if (!product_id || !week_number) {
    return res.status(400).json({ error: 'Produto e semana são obrigatórios.' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Arquivo não enviado.' });
  }

  const fileUrl = `/uploads/mentoria/${req.file.filename}`;
  const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

  db.get(
    `
    SELECT id
    FROM mentoria_tasks
    WHERE user_id = ?
    AND product_id = ?
    AND week_number = ?
    `,
    [req.user.id, product_id, week_number],
    (err, existing) => {
      if (err) return res.status(400).json({ error: err.message });

      if (existing) {
        db.run(
          `
          UPDATE mentoria_tasks
          SET task_title = ?,
    task_file_url = ?,
    task_original_name = ?,
    task_uploaded_at = CURRENT_TIMESTAMP,

    report_file_url = NULL,
    report_original_name = NULL,
    report_uploaded_at = NULL,

    status = 'task_uploaded',
    updated_at = CURRENT_TIMESTAMP
   WHERE id = ?
          `,
          [
            task_title || `Tarefa da semana ${week_number}`,
            fileUrl,
            originalName,
            existing.id
          ],
          function (err2) {
            if (err2) return res.status(400).json({ error: err2.message });

            res.json({
              success: true,
              id: existing.id,
              file_url: fileUrl,
              original_name: originalName,
              status: 'task_uploaded'
            });
          }
        );
      } else {
        db.run(
          `
          INSERT INTO mentoria_tasks
          (user_id, product_id, week_number, task_title, task_file_url, task_original_name, task_uploaded_at, status)
          VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'task_uploaded')
          `,
          [
            req.user.id,
            product_id,
            week_number,
            task_title || `Tarefa da semana ${week_number}`,
            fileUrl,
            originalName
          ],
          function (err3) {
            if (err3) return res.status(400).json({ error: err3.message });

            res.json({
              success: true,
              id: this.lastID,
              file_url: fileUrl,
              original_name: originalName,
              status: 'task_uploaded'
            });
          }
        );
      }
    }
  );
});

app.get('/admin/mentoria-tasks', auth, adminOnly, (req, res) => {
  db.all(
    `
    SELECT
      mt.*,
      u.name AS student_name,
      u.email AS student_email,
      sp.product_name
    FROM mentoria_tasks mt
    LEFT JOIN users u ON u.id = mt.user_id
    LEFT JOIN student_products sp ON sp.id = mt.product_id
    ORDER BY mt.updated_at DESC
    `,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/admin/mentoria-tasks/:id/report', auth, adminOnly, uploadSingle('report_file'), (req, res) => {
  const { id } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'Relatório não enviado.' });
  }

  const fileUrl = `/uploads/mentoria/${req.file.filename}`;
  const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

  db.get(
    `
    SELECT
      mt.*,
      sp.product_name
    FROM mentoria_tasks mt
    LEFT JOIN student_products sp ON sp.id = mt.product_id
    WHERE mt.id = ?
    `,
    [id],
    (err, task) => {
      if (err || !task) {
        return res.status(404).json({ error: 'Tarefa não encontrada.' });
      }

      db.run(
        `
        UPDATE mentoria_tasks
        SET report_file_url = ?,
            report_original_name = ?,
            report_uploaded_at = CURRENT_TIMESTAMP,
            status = 'report_uploaded',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [fileUrl, originalName, id],
        function (err2) {
          if (err2) return res.status(400).json({ error: err2.message });

          const now = new Date();
const dataHora = now.toLocaleString('pt-BR', {
  timeZone: 'America/Sao_Paulo',
  dateStyle: 'short',
  timeStyle: 'short'
});

db.run(
  `console.log('DEBUG RELATORIO NOW:', new Date().toISOString());
console.log('DEBUG RELATORIO dataHora:', dataHora);
  INSERT INTO notices (title, message, target, type)
  VALUES (?, ?, ?, ?)
  `,
  [
    `Relatório disponível — Semana ${String(task.week_number).padStart(2, '0')}`,
    `Seu relatório da ${task.product_name || 'Mentoria'} referente à Semana ${String(task.week_number).padStart(2, '0')} foi enviado em ${dataHora}.`,
    `user_${task.user_id}`,
    'mentoria'
  ],
  () => {}
);

          res.json({
            success: true,
            file_url: fileUrl,
            original_name: originalName,
            status: 'report_uploaded'
          });
        }
      );
    }
  );
});

/* Compatibilidade com admin antigo, caso alguma tela chame /api */
app.get('/api/mentoria/tasks', auth, adminOnly, (req, res) => {
  db.all(
    `
    SELECT
      mt.*,
      u.name AS student_name,
      u.email AS student_email,
      sp.product_name
    FROM mentoria_tasks mt
    LEFT JOIN users u ON u.id = mt.user_id
    LEFT JOIN student_products sp ON sp.id = mt.product_id
    ORDER BY mt.updated_at DESC
    `,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(rows);
    }
  );
});

/* =========================================================
   EXTRA MATERIALS
========================================================= */

function safeJsonParseField(value, fallback) {
  if (!value) return fallback;
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return parsed || fallback;
  } catch {
    return fallback;
  }
}

function extraMaterialRow(row) {
  if (!row) return row;
  return {
    ...row,
    active: row.active === 1 || row.active === true,
    product_types: safeJsonParseField(row.product_types, []),
    course_ids: safeJsonParseField(row.course_ids, []),
    course_refs: safeJsonParseField(row.course_refs, []),
    student_ids: safeJsonParseField(row.student_ids, []),
    student_refs: safeJsonParseField(row.student_refs, [])
  };
}

function normalizeExtraArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  return [String(value)].filter(Boolean);
}

function normalizeExtraRefs(value) {
  return Array.isArray(value) ? value : [];
}

app.get('/admin/extra-materials', auth, adminOnly, (req, res) => {
  db.all(
    `SELECT * FROM extra_materials ORDER BY id DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json((rows || []).map(extraMaterialRow));
    }
  );
});

app.post('/admin/extra-materials', auth, adminOnly, (req, res) => {
  const {
    title,
    description,
    url,
    target,
    product_types,
    course_ids,
    course_refs,
    student_ids,
    student_refs,
    active
  } = req.body;

  if (!title || !url) {
    return res.status(400).json({ error: 'Informe título e link do material.' });
  }

  db.run(
    `
    INSERT INTO extra_materials
    (title, description, url, target, product_types, course_ids, course_refs, student_ids, student_refs, active, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `,
    [
      title,
      description || '',
      url,
      target || 'draft',
      JSON.stringify(normalizeExtraArray(product_types)),
      JSON.stringify(normalizeExtraArray(course_ids)),
      JSON.stringify(normalizeExtraRefs(course_refs)),
      JSON.stringify(normalizeExtraArray(student_ids)),
      JSON.stringify(normalizeExtraRefs(student_refs)),
      active === false ? 0 : 1
    ],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });

      db.get(`SELECT * FROM extra_materials WHERE id = ?`, [this.lastID], (err2, row) => {
        if (err2) return res.status(400).json({ error: err2.message });
        res.json(extraMaterialRow(row));
      });
    }
  );
});

app.patch('/admin/extra-materials/:id', auth, adminOnly, (req, res) => {
  const {
    title,
    description,
    url,
    target,
    product_types,
    course_ids,
    course_refs,
    student_ids,
    student_refs,
    active
  } = req.body;

  db.run(
    `
    UPDATE extra_materials
    SET title = COALESCE(?, title),
        description = COALESCE(?, description),
        url = COALESCE(?, url),
        target = COALESCE(?, target),
        product_types = ?,
        course_ids = ?,
        course_refs = ?,
        student_ids = ?,
        student_refs = ?,
        active = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
    `,
    [
      title || null,
      description ?? null,
      url || null,
      target || 'draft',
      JSON.stringify(normalizeExtraArray(product_types)),
      JSON.stringify(normalizeExtraArray(course_ids)),
      JSON.stringify(normalizeExtraRefs(course_refs)),
      JSON.stringify(normalizeExtraArray(student_ids)),
      JSON.stringify(normalizeExtraRefs(student_refs)),
      active === false ? 0 : 1,
      req.params.id
    ],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      if (!this.changes) return res.status(404).json({ error: 'Material extra não encontrado.' });

      db.get(`SELECT * FROM extra_materials WHERE id = ?`, [req.params.id], (err2, row) => {
        if (err2) return res.status(400).json({ error: err2.message });
        res.json(extraMaterialRow(row));
      });
    }
  );
});

app.delete('/admin/extra-materials/:id', auth, adminOnly, (req, res) => {
  db.run(`DELETE FROM extra_materials WHERE id = ?`, [req.params.id], function (err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/student/extra-materials', auth, (req, res) => {
  db.all(
    `SELECT * FROM extra_materials WHERE active = 1 AND target <> 'draft' ORDER BY id DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });

      const userId = String(req.user.id);
      const allowed = (rows || []).map(extraMaterialRow).filter(m => {
        const target = m.target || 'draft';
        if (target === 'all') return true;
        if (target === 'students') return (m.student_ids || []).map(String).includes(userId);
        return true;
      });

      res.json(allowed);
    }
  );
});

app.post('/admin/courses', auth, adminOnly, (req, res) => {
  const {
    id,
    local_id,
    tipo,
    product_type,
    nome,
    product_name,
    apelido,
    dataInicio,
    hora,
    sessoes,
    status
  } = req.body;

  const tipoFinal = tipo || product_type;
  const nomeFinal = nome || product_name;

  if (!tipoFinal || !nomeFinal) {
    return res.status(400).json({ error: 'Informe tipo e nome do curso.' });
  }

  const localId = String(local_id || id || '');

  db.get(
    `SELECT id FROM courses WHERE local_id = ?`,
    [localId],
    (err, existing) => {
      if (err) return res.status(400).json({ error: err.message });

      if (existing) {
        db.run(
          `
          UPDATE courses
          SET tipo = ?, nome = ?, apelido = ?, dataInicio = ?, hora = ?, sessoes = ?, status = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
          `,
          [
            tipoFinal,
            nomeFinal,
            apelido || '',
            dataInicio || '',
            hora || '',
            JSON.stringify(Array.isArray(sessoes) ? sessoes : []),
            status || 'ativo',
            existing.id
          ],
          function (err2) {
            if (err2) return res.status(400).json({ error: err2.message });
            res.json({ success: true, id: existing.id });
          }
        );
      } else {
        db.run(
          `
          INSERT INTO courses
          (local_id, tipo, nome, apelido, dataInicio, hora, sessoes, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            localId,
            tipoFinal,
            nomeFinal,
            apelido || '',
            dataInicio || '',
            hora || '',
            JSON.stringify(Array.isArray(sessoes) ? sessoes : []),
            status || 'ativo'
          ],
          function (err3) {
            if (err3) return res.status(400).json({ error: err3.message });
            res.json({ success: true, id: this.lastID });
          }
        );
      }
    }
  );
});

app.get('/student/courses', auth, (req, res) => {
  db.all(
    `
    SELECT *
    FROM courses
    WHERE status = 'ativo'
    AND tipo IN ('workshop', 'imersao', 'mentoria')
    ORDER BY dataInicio ASC, hora ASC
    `,
    [],
    (err, rows) => {
      if (err) return res.status(400).json({ error: err.message });

      res.json((rows || []).map(r => ({
        ...r,
        id: r.local_id || r.id,
        server_id: r.id,
        sessoes: r.sessoes ? JSON.parse(r.sessoes) : []
      })));
    }
  );
});

/* =========================================================
   DEBUG / ROOT / SERVER
========================================================= */

app.get('/debug/users', (req, res) => {
  db.all(`SELECT id, name, email, role, status FROM users`, [], (err, rows) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/', (req, res) => {
  res.send('Backend Personal do Zero online');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
