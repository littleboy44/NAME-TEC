
import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL 환경변수가 설정되지 않았습니다.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

export async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    INSERT INTO sites (name, slug)
    VALUES ('NAME-TEC', 'name-tec')
    ON CONFLICT (slug) DO NOTHING;

    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      credits INTEGER DEFAULT 0,
      premium_until TEXT,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      password_hash TEXT,
      site_id BIGINT REFERENCES sites(id)
    );

    CREATE TABLE IF NOT EXISTS admins (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      payment_id TEXT UNIQUE NOT NULL,
      amount INTEGER NOT NULL,
      product_type TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      site_id BIGINT REFERENCES sites(id)
    );

    CREATE TABLE IF NOT EXISTS credit_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_id BIGINT REFERENCES admins(id),
      user_id BIGINT NOT NULL REFERENCES users(id),
      change_amount INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      site_id BIGINT REFERENCES sites(id)
    );

      ALTER TABLE credit_logs
      ALTER COLUMN admin_id DROP NOT NULL;

    CREATE TABLE IF NOT EXISTS payment_orders (
      order_id TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      site_id BIGINT NOT NULL REFERENCES sites(id),
      product_type TEXT NOT NULL,
      amount INTEGER NOT NULL,
      credits INTEGER NOT NULL DEFAULT 0,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS payment_key TEXT;

    ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_orders_payment_key
    ON payment_orders(payment_key);

    CREATE INDEX IF NOT EXISTS idx_users_site ON users(site_id);
    CREATE INDEX IF NOT EXISTS idx_payments_site ON payments(site_id);
    CREATE INDEX IF NOT EXISTS idx_credit_logs_site ON credit_logs(site_id);
  -- 방문자 정보
CREATE TABLE IF NOT EXISTS visitors (
  id BIGSERIAL PRIMARY KEY,
  site_id BIGINT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  visitor_id TEXT NOT NULL,
  first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(site_id, visitor_id)
);

-- 방문 세션
CREATE TABLE IF NOT EXISTS visitor_sessions (
  id BIGSERIAL PRIMARY KEY,
  site_id BIGINT NOT NULL,
  visitor_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(site_id, session_id),
  FOREIGN KEY (site_id, visitor_id)
    REFERENCES visitors(site_id, visitor_id)
    ON DELETE CASCADE
);

-- 페이지 조회 기록
CREATE TABLE IF NOT EXISTS page_views (
  id BIGSERIAL PRIMARY KEY,
  site_id BIGINT NOT NULL,
  visitor_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  path TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (site_id, visitor_id)
    REFERENCES visitors(site_id, visitor_id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_visitors_site
ON visitors(site_id);

CREATE INDEX IF NOT EXISTS idx_sessions_active
ON visitor_sessions(site_id, last_seen);

CREATE INDEX IF NOT EXISTS idx_page_views_site_date
ON page_views(site_id, created_at);

CREATE INDEX IF NOT EXISTS idx_page_views_path
ON page_views(site_id, path);
  `);

  console.log("NAME-TEC PostgreSQL 데이터베이스 준비 완료!");
}

export default pool;
