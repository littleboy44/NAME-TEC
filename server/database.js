
import Database from "better-sqlite3";

const db = new Database(process.env.DB_PATH || "nametec.db");

// 회원 정보
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    credits INTEGER DEFAULT 0,
    premium_until TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// 기존 회원 테이블에 비밀번호 해시 컬럼 추가
const userColumns = db.prepare(
  "PRAGMA table_info(users)"
).all();

if (!userColumns.some(column => column.name === "password_hash")) {
  db.exec("ALTER TABLE users ADD COLUMN password_hash TEXT");
}

// 결제 내역
db.exec(`
  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    payment_id TEXT UNIQUE NOT NULL,
    amount INTEGER NOT NULL,
    product_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// 관리자 전용 정보
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// 관리자 이용권 변경 기록
db.exec(`
  CREATE TABLE IF NOT EXISTS credit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    change_amount INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admins(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);


// 통합 관리 대상 사이트 등록
db.exec(`
  CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// 첫 번째 사이트 NAME-TEC 등록
db.prepare(`
  INSERT OR IGNORE INTO sites (name, slug)
  VALUES (?, ?)
`).run("NAME-TEC", "name-tec");

// NAME-TEC의 사이트 번호 가져오기
const mainSite = db.prepare(
  "SELECT id FROM sites WHERE slug = ?"
).get("name-tec");

// 기존 테이블에 사이트 구분 번호 추가
for (const table of ["users", "payments", "credit_logs"]) {
  const columns = db.prepare(
    `PRAGMA table_info(${table})`
  ).all();

  if (!columns.some(column => column.name === "site_id")) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN site_id INTEGER`);
  }

  // 기존 데이터는 NAME-TEC 소속으로 지정
  db.prepare(
    `UPDATE ${table} SET site_id = ? WHERE site_id IS NULL`
  ).run(mainSite.id);
}

// 사이트별 조회를 위한 인덱스
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_users_site
  ON users(site_id);

  CREATE INDEX IF NOT EXISTS idx_payments_site
  ON payments(site_id);

  CREATE INDEX IF NOT EXISTS idx_credit_logs_site
  ON credit_logs(site_id);
`);


console.log("NAME-TEC 데이터베이스 준비 완료!");

export default db;
