
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
      admin_id BIGINT NOT NULL REFERENCES admins(id),
      user_id BIGINT NOT NULL REFERENCES users(id),
      change_amount INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      site_id BIGINT REFERENCES sites(id)
    );

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

    CREATE INDEX IF NOT EXISTS idx_users_site ON users(site_id);
    CREATE INDEX IF NOT EXISTS idx_payments_site ON payments(site_id);
    CREATE INDEX IF NOT EXISTS idx_credit_logs_site ON credit_logs(site_id);
  `);

  console.log("NAME-TEC PostgreSQL 데이터베이스 준비 완료!");
}

export default pool;
