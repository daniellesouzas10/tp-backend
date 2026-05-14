require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const db = require('./database');

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

/* INIT DB */
const schema = fs.readFileSync('./schema.sql', 'utf8');
db.exec(schema);

db.run(`ALTER TABLE users ADD COLUMN phone TEXT`, () => {});
db.run(`ALTER TABLE users ADD COLUMN address TEXT`, () => {});

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

/* MIDDLEWARE AUTH */
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

/* AUTH */

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

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
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
    }
  );
});

/* ADMIN — ALUNOS */

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
        db.run(
          `INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)`,
          [userId, plan_id]
        );
      }

      res.json({
        id: userId,
        name,
        email,
        role: 'student',
        plan_id
      });
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
      users.status,
      plans.name AS plan
    FROM users
    LEFT JOIN user_plans ON user_plans.user_id = users.id
    LEFT JOIN plans ON plans.id = user_plans.plan_id
    WHERE users.role = 'student'
    ORDER BY users.created_at DESC
    `,
    [],
    (err, rows) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json(rows);
    }
  );
});

app.patch('/admin/students/:id/status', auth, adminOnly, (req, res) => {
  const { status } = req.body;

  db.run(
    `UPDATE users SET status = ? WHERE id = ?`,
    [status, req.params.id],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({ success: true });
    }
  );
});

app.patch('/admin/students/:id/plan', auth, adminOnly, (req, res) => {
  const { plan_id } = req.body;

  db.run(
    `DELETE FROM user_plans WHERE user_id = ?`,
    [req.params.id],
    () => {
      db.run(
        `INSERT INTO user_plans (user_id, plan_id) VALUES (?, ?)`,
        [req.params.id, plan_id],
        function (err) {
          if (err) {
            return res.status(400).json({ error: err.message });
          }

          res.json({ success: true });
        }
      );
    }
  );
});

/* ADMIN — PLANOS */

app.post('/admin/plans', auth, adminOnly, (req, res) => {
  const { name, description } = req.body;

  db.run(
    `INSERT INTO plans (name, description) VALUES (?, ?)`,
    [name, description],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({ id: this.lastID, name, description });
    }
  );
});

app.get('/admin/plans', auth, adminOnly, (req, res) => {
  db.all(`SELECT * FROM plans ORDER BY id DESC`, [], (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }

    res.json(rows);
  });
});

/* ADMIN — MÓDULOS */

app.post('/admin/modules', auth, adminOnly, (req, res) => {
  const { title, description, order_number, status } = req.body;

  db.run(
    `INSERT INTO modules (title, description, order_number, status) VALUES (?, ?, ?, ?)`,
    [title, description, order_number, status || 'published'],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({ id: this.lastID, title, description });
    }
  );
});

app.get('/admin/modules', auth, adminOnly, (req, res) => {
  db.all(`SELECT * FROM modules ORDER BY order_number ASC`, [], (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }

    res.json(rows);
  });
});

/* ADMIN — AULAS */

app.post('/admin/lessons', auth, adminOnly, (req, res) => {
  const {
    module_id,
    title,
    video_url,
    description,
    duration,
    order_number,
    status
  } = req.body;

  db.run(
    `
    INSERT INTO lessons 
    (module_id, title, video_url, description, duration, order_number, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      module_id,
      title,
      video_url,
      description,
      duration,
      order_number,
      status || 'published'
    ],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

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
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json(rows);
    }
  );
});

/* ADMIN — LIBERAR CONTEÚDO PARA PLANO */

app.post('/admin/access', auth, adminOnly, (req, res) => {
  const { plan_id, module_id, lesson_id } = req.body;

  db.run(
    `INSERT INTO plan_access (plan_id, module_id, lesson_id) VALUES (?, ?, ?)`,
    [plan_id, module_id || null, lesson_id || null],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({ success: true, id: this.lastID });
    }
  );
});

/* ADMIN — AVISOS */

app.post('/admin/notices', auth, adminOnly, (req, res) => {
  const { title, message, target, type } = req.body;

  db.run(
    `INSERT INTO notices (title, message, target, type) VALUES (?, ?, ?, ?)`,
    [title, message, target || 'all', type || 'info'],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({ id: this.lastID, title, message });
    }
  );
});

app.get('/admin/notices', auth, adminOnly, (req, res) => {
  db.all(`SELECT * FROM notices ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }

    res.json(rows);
  });
});

/* ADMIN — LIBERAÇÃO UNIFICADA DE PRODUTO */

app.post('/admin/product-release', auth, adminOnly, (req, res) => {
  const {
    user_id,
    product_type,
    product_name,
    release_datetime,
    main_url,
    material_url,
    bonus_url,
    notes
  } = req.body;

  if (!user_id || !product_type || !product_name || !release_datetime) {
    return res.status(400).json({
      error: 'Informe aluno, produto, nome do produto e data/hora de liberação.'
    });
  }

  db.run(
    `
    INSERT INTO student_products
    (
      user_id,
      product_type,
      product_name,
      release_datetime,
      main_url,
      material_url,
      bonus_url,
      notes,
      access_status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `,
    [
      user_id,
      product_type,
      product_name,
      release_datetime,
      main_url || null,
      material_url || null,
      bonus_url || null,
      notes || null
    ],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({
        success: true,
        id: this.lastID,
        message: 'Produto liberado para o aluno.'
      });
    }
  );
});

/* ALUNO — MEUS DADOS */

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
      if (err) {
        return res.status(400).json({ error: err.message });
      }

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

/* ALUNO — PRODUTOS LIBERADOS */

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
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      const now = new Date();

      const formatted = products.map(product => {
        const releaseDate = new Date(product.release_datetime);

        return {
          ...product,
          released: now >= releaseDate
        };
      });

      res.json(formatted);
    }
  );
});

/* COMPATIBILIDADE — WORKSHOP DO ALUNO */

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
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      if (!product) {
        return res.json(null);
      }

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
              product.material_url
                ? {
                    title: 'Material do Aluno',
                    file_url: product.material_url
                  }
                : null,
              product.bonus_url
                ? {
                    title: 'Autodiagnóstico da Carreira',
                    file_url: product.bonus_url
                  }
                : null
            ].filter(Boolean)
          : []
      });
    }
  );
});

/* ALUNO — CONTEÚDOS LIBERADOS */

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
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json(rows);
    }
  );
});

/* ALUNO — AVISOS */

app.get('/student/notices', auth, (req, res) => {
  db.all(
    `
    SELECT * FROM notices
    WHERE target = 'all'
    ORDER BY created_at DESC
    LIMIT 10
    `,
    [],
    (err, rows) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json(rows);
    }
  );
});

/* ALUNO — PROGRESSO */

app.post('/student/progress', auth, (req, res) => {
  const { lesson_id, completed, progress_percent } = req.body;

  db.run(
    `
    INSERT INTO progress (user_id, lesson_id, completed, progress_percent)
    VALUES (?, ?, ?, ?)
    `,
    [
      req.user.id,
      lesson_id,
      completed ? 1 : 0,
      progress_percent || 0
    ],
    function (err) {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json({ success: true });
    }
  );
});

app.get('/student/progress', auth, (req, res) => {
  db.all(
    `SELECT * FROM progress WHERE user_id = ?`,
    [req.user.id],
    (err, rows) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json(rows);
    }
  );
});

/* DEBUG */

app.get('/debug/users', (req, res) => {
  db.all(
    `SELECT id, name, email, role, status FROM users`,
    [],
    (err, rows) => {
      if (err) {
        return res.status(400).json({ error: err.message });
      }

      res.json(rows);
    }
  );
});

/* SERVER */

app.get('/', (req, res) => {
  res.send('Backend Personal do Zero online 🚀');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
