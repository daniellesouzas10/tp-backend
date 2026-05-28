CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'student',
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  plan_id INTEGER NOT NULL,
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS modules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  order_number INTEGER,
  status TEXT DEFAULT 'published'
);

CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  module_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  video_url TEXT,
  description TEXT,
  duration TEXT,
  order_number INTEGER,
  status TEXT DEFAULT 'published'
);

CREATE TABLE IF NOT EXISTS plan_access (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  module_id INTEGER,
  lesson_id INTEGER
);

CREATE TABLE IF NOT EXISTS notices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  target TEXT DEFAULT 'all',
  type TEXT DEFAULT 'info',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  lesson_id INTEGER NOT NULL,
  completed INTEGER DEFAULT 0,
  progress_percent INTEGER DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workshops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  event_date TEXT,
  event_time TEXT,
  live_url TEXT,
  replay_url TEXT,
  status TEXT DEFAULT 'scheduled',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workshop_materials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workshop_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  file_url TEXT,
  visible_to_student INTEGER DEFAULT 1,
  release_mode TEXT DEFAULT 'on_start',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS student_workshops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  workshop_id INTEGER NOT NULL,
  event_datetime TEXT NOT NULL,
  access_status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

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
);

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
);

CREATE TABLE IF NOT EXISTS extra_materials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  title TEXT NOT NULL,
  description TEXT,

  url TEXT NOT NULL,

  target TEXT DEFAULT 'all',

  product_type TEXT,
  student_id INTEGER,

  active INTEGER DEFAULT 1,

  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
