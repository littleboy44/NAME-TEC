
import "dotenv/config";
import bcrypt from "bcryptjs";
import db from "./database.js";

const email = process.env.ADMIN_EMAIL;
const password = process.env.ADMIN_PASSWORD;

if (!email || !password) {
  console.error(".env에 관리자 이메일과 비밀번호가 있는지 확인하세요.");
  process.exit(1);
}

const passwordHash = await bcrypt.hash(password, 12);

db.prepare(`
  INSERT INTO admins (email, password_hash)
  VALUES (?, ?)
  ON CONFLICT(email)
  DO UPDATE SET password_hash = excluded.password_hash
`).run(email, passwordHash);

console.log("관리자 비밀번호 재등록 완료!");
db.close();
