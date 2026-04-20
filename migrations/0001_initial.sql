-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  company_name TEXT NOT NULL,
  representative TEXT NOT NULL,
  business_number TEXT NOT NULL,
  phone TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 인증신청 테이블
CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  cert_type TEXT NOT NULL CHECK(cert_type IN ('basic','change','report')),
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','in_progress','completed')),
  title TEXT NOT NULL,
  brand TEXT,
  model TEXT,
  model_year TEXT,
  prev_cert_number TEXT,
  change_item TEXT,
  change_reason TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 서류별 데이터 저장 테이블
CREATE TABLE IF NOT EXISTS form_data (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id INTEGER NOT NULL,
  form_type TEXT NOT NULL,
  data TEXT NOT NULL DEFAULT '{}',
  completed INTEGER NOT NULL DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_applications_user_id ON applications(user_id);
CREATE INDEX IF NOT EXISTS idx_form_data_application_id ON form_data(application_id);
CREATE INDEX IF NOT EXISTS idx_form_data_form_type ON form_data(form_type);
