import "dotenv/config";
import bcrypt from "bcrypt";
import express from "express";
import cors from "cors";
import db from "./database.js";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(cors());
app.use(express.json());

// 일반 회원가입 API
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        message: "올바른 이메일과 8~72자의 비밀번호를 입력해 주세요."
      });
    }

    if (!JWT_SECRET) {
      return res.status(500).json({
        message: "서버 인증 설정을 확인해 주세요."
      });
    }

    const site = db.prepare(
      "SELECT id FROM sites WHERE name = ?"
    ).get("NAME-TEC");

    if (!site) {
      return res.status(500).json({
        message: "사이트 정보를 찾을 수 없습니다."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = db.prepare(
      "SELECT id FROM users WHERE email = ? AND site_id = ?"
    ).get(normalizedEmail, site.id);

    if (existingUser) {
      return res.status(409).json({
        message: "이미 가입된 이메일입니다."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (email, password_hash, site_id)
      VALUES (?, ?, ?)
    `).run(normalizedEmail, passwordHash, site.id);

    const token = jwt.sign(
      {
        userId: Number(result.lastInsertRowid),
        siteId: site.id
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "회원가입 성공",
      token
    });

  } catch (error) {
    console.error("회원가입 오류:", error);

    res.status(500).json({
      message: "회원가입에 실패했습니다."
    });
  }
});


// 일반 회원 로그인 API
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "이메일과 비밀번호를 입력해 주세요."
      });
    }

    if (!JWT_SECRET) {
      return res.status(500).json({
        message: "서버 인증 설정을 확인해 주세요."
      });
    }

    const site = db.prepare(
      "SELECT id FROM sites WHERE name = ?"
    ).get("NAME-TEC");

    if (!site) {
      return res.status(500).json({
        message: "사이트 정보를 찾을 수 없습니다."
      });
    }

    const user = db.prepare(`
      SELECT id, email, password_hash, credits
      FROM users
      WHERE email = ? AND site_id = ?
    `).get(email.trim().toLowerCase(), site.id);

    if (!user || !user.password_hash) {
      return res.status(401).json({
        message: "이메일 또는 비밀번호가 올바르지 않습니다."
      });
    }

    const passwordMatch = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        message: "이메일 또는 비밀번호가 올바르지 않습니다."
      });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        siteId: site.id
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "로그인 성공",
      token,
      user: {
        id: user.id,
        email: user.email,
        credits: user.credits
      }
    });

  } catch (error) {
    console.error("로그인 오류:", error);

    res.status(500).json({
      message: "로그인에 실패했습니다."
    });
  }
});

// 일반 회원 인증 미들웨어
function verifyUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "로그인이 필요합니다."
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    req.userId = decoded.userId;
    req.siteId = decoded.siteId;

    next();

  } catch (error) {
    return res.status(401).json({
      message: "로그인 정보가 유효하지 않습니다."
    });
  }
}


 // 결제 주문 생성 API
app.post("/api/payments/create-order", verifyUser, (req, res) => {
  try {
    const { productType } = req.body;

    const products = {
      PLUS: {
        name: "NAME-TEC PLUS",
        amount: 990
      },
      PREMIUM: {
        name: "NAME-TEC PREMIUM",
        amount: 2900
      }
    };

    const product = products[productType];

    if (!product) {
      return res.status(400).json({
        message: "올바르지 않은 상품입니다."
      });
    }

    const orderId = randomUUID();

    db.prepare(`
      INSERT INTO payment_orders
      (order_id, user_id, site_id, product_type, amount, credits)
      VALUES (?, ?, ?, ?, ?, 0)
    `).run(
      orderId,
      req.userId,
      req.siteId,
      productType,
      product.amount
    );

    res.status(201).json({
      message: "결제 주문 생성 성공",
      orderId,
      orderName: product.name,
      amount: product.amount
    });

  } catch (error) {
    console.error("결제 주문 생성 오류:", error);

    res.status(500).json({
      message: "결제 주문 생성에 실패했습니다."
    });
  }
});


// 관리자 페이지 제공
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "NAME-TEC 서버가 준비되었습니다."
  });
});


app.get("/api/db-health", (req, res) => {
  try {
    db.prepare("SELECT 1").get();
    res.json({
      status: "ok",
      message: "데이터베이스 연결 정상"
    });
  } catch (error) {
    res.status(500).json({
      status: "error"
    });
  }
});


const adminEmail = process.env.ADMIN_EMAIL;
const adminPassword = process.env.ADMIN_PASSWORD;

if (!adminEmail || !adminPassword || !process.env.JWT_SECRET) {
  throw new Error("관리자 환경설정이 누락되었습니다. .env 파일을 확인하세요.");
}

const existingAdmin = db.prepare(
  "SELECT id FROM admins WHERE email = ?"
).get(adminEmail);

if (!existingAdmin) {
  const passwordHash = await bcrypt.hash(adminPassword, 12);

  db.prepare(
    "INSERT INTO admins (email, password_hash) VALUES (?, ?)"
  ).run(adminEmail, passwordHash);

  console.log("관리자 계정 등록 완료!");
}


app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "이메일과 비밀번호를 입력해 주세요."
      });
    }

    const admin = db.prepare(
      "SELECT * FROM admins WHERE email = ?"
    ).get(email);

    if (!admin) {
      return res.status(401).json({
        message: "로그인 정보가 올바르지 않습니다."
      });
    }

    const passwordMatch = await bcrypt.compare(
      password,
      admin.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        message: "로그인 정보가 올바르지 않습니다."
      });
    }

    const token = jwt.sign(
      { adminId: admin.id, role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "관리자 로그인 성공",
      token
    });

  } catch (error) {
    console.error("관리자 로그인 오류:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다."
    });
  }
});


function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "관리자 로그인이 필요합니다."
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({
        message: "관리자 권한이 없습니다."
      });
    }

    req.adminId = decoded.adminId;
    next();

  } catch (error) {
    return res.status(401).json({
      message: "인증이 만료되었거나 유효하지 않습니다."
    });
  }
}

app.get("/api/admin/dashboard", verifyAdmin, (req, res) => {
  try {
    const admin = db.prepare(
      "SELECT id, email, created_at FROM admins WHERE id = ?"
    ).get(req.adminId);

    const totalMembers = db.prepare(`
      SELECT COUNT(*) AS count FROM users
    `).get().count;

    const totalPayments = db.prepare(`
      SELECT COUNT(*) AS count FROM payments
    `).get().count;

    const totalCreditLogs = db.prepare(`
      SELECT COUNT(*) AS count FROM credit_logs
    `).get().count;
    
    const totalSites = db.prepare(`
      SELECT COUNT(*) AS count FROM sites
    `).get().count;

    res.json({
      message: "관리자 인증 및 전체 통계 조회 성공",
      admin,
  stats: {
    totalMembers,
    totalPayments,
    totalCreditLogs,
    totalSites
}
    });

  } catch (error) {
    console.error("대시보드 조회 오류:", error);

    res.status(500).json({
      message: "대시보드 정보를 불러오지 못했습니다."
    });
  }
});


 // 관리자 전용 사이트별 회원 조회
app.get("/api/admin/members", verifyAdmin, (req, res) => {
  try {
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({
        message: "올바른 사이트 번호를 입력해 주세요."
      });
    }

    const members = db.prepare(`
      SELECT
        id,
        email,
        credits,
        premium_until,
        created_at
      FROM users
      WHERE site_id = ?
      ORDER BY id DESC
    `).all(siteId);

    res.json({
      message: "사이트별 회원 목록 조회 성공",
      siteId,
      total: members.length,
      members
    });

  } catch (error) {
    console.error("회원 조회 오류:", error);

    res.status(500).json({
      message: "회원 목록을 불러오지 못했습니다."
    });
  }
});


// 관리자 전용 사이트별 결제 내역 조회
app.get("/api/admin/payments", verifyAdmin, (req, res) => {
  try {
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({
        message: "올바른 사이트 번호를 입력해 주세요."
      });
    }

    const payments = db.prepare(`
      SELECT
        payments.id,
        payments.user_id,
        users.email,
        payments.payment_id,
        payments.amount,
        payments.product_type,
        payments.status,
        payments.created_at
      FROM payments
      LEFT JOIN users ON payments.user_id = users.id
      WHERE payments.site_id = ?
      ORDER BY payments.id DESC
    `).all(siteId);

    res.json({
      message: "사이트별 결제 내역 조회 성공",
      siteId,
      total: payments.length,
      payments
    });

  } catch (error) {
    console.error("결제 조회 오류:", error);

    res.status(500).json({
      message: "결제 내역을 불러오지 못했습니다."
    });
  }
});



// 관리자 전용 사이트별 회원 상세 조회
app.get("/api/admin/members/:id", verifyAdmin, (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(memberId) || memberId <= 0) {
      return res.status(400).json({
        message: "올바르지 않은 회원 번호입니다."
      });
    }

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({
        message: "올바른 사이트 번호를 입력해 주세요."
      });
    }

    const member = db.prepare(`
      SELECT id, email, credits, premium_until, created_at
      FROM users
      WHERE id = ? AND site_id = ?
    `).get(memberId, siteId);

    if (!member) {
      return res.status(404).json({
        message: "해당 사이트에서 회원을 찾을 수 없습니다."
      });
    }

    const payments = db.prepare(`
      SELECT payment_id, amount, product_type, status, created_at
      FROM payments
      WHERE user_id = ? AND site_id = ?
      ORDER BY id DESC
    `).all(memberId, siteId);

    res.json({
      message: "회원 상세 조회 성공",
      member,
      payments
    });

  } catch (error) {
    console.error("회원 상세 조회 오류:", error);

    res.status(500).json({
      message: "회원 정보를 불러오지 못했습니다."
    });
  }
});


// 관리자 전용 사이트별 이용권 지급 및 차감
app.post("/api/admin/members/:id/credits", verifyAdmin, (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const siteId = Number(req.query.siteId);
    const { amount, reason } = req.body;

    if (!Number.isInteger(memberId) || memberId <= 0) {
      return res.status(400).json({
        message: "올바르지 않은 회원 번호입니다."
      });
    }

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({
        message: "올바른 사이트 번호를 입력해 주세요."
      });
    }

    if (!Number.isInteger(amount) || amount === 0 || Math.abs(amount) > 1000) {
      return res.status(400).json({
        message: "변경 횟수는 -1000부터 1000 사이의 0이 아닌 정수여야 합니다."
      });
    }

    if (typeof reason !== "string" || !reason.trim() || reason.length > 200) {
      return res.status(400).json({
        message: "변경 사유를 1~200자로 입력해 주세요."
      });
    }

    const member = db.prepare(
      "SELECT id, credits FROM users WHERE id = ? AND site_id = ?"
    ).get(memberId, siteId);

    if (!member) {
      return res.status(404).json({
        message: "해당 사이트에서 회원을 찾을 수 없습니다."
      });
    }

    if (member.credits + amount < 0) {
      return res.status(400).json({
        message: "이용권 잔액보다 많이 차감할 수 없습니다."
      });
    }

    const updateCredits = db.transaction(() => {
      db.prepare(
        "UPDATE users SET credits = credits + ? WHERE id = ? AND site_id = ?"
      ).run(amount, memberId, siteId);

      db.prepare(`
        INSERT INTO credit_logs
        (admin_id, user_id, change_amount, reason, site_id)
        VALUES (?, ?, ?, ?, ?)
      `).run(req.adminId, memberId, amount, reason.trim(), siteId);
    });

    updateCredits();

    const updatedMember = db.prepare(
      "SELECT id, email, credits FROM users WHERE id = ? AND site_id = ?"
    ).get(memberId, siteId);

    res.json({
      message: "이용권 변경 성공",
      member: updatedMember
    });

  } catch (error) {
    console.error("이용권 변경 오류:", error);

    res.status(500).json({
      message: "이용권 변경에 실패했습니다."
    });
  }
});




// 관리자 전용 사이트별 이용권 변경 기록 조회
app.get("/api/admin/credit-logs", verifyAdmin, (req, res) => {
  try {
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({
        message: "올바른 사이트 번호를 입력해 주세요."
      });
    }

    const logs = db.prepare(`
      SELECT
        credit_logs.id,
        credit_logs.admin_id,
        admins.email AS admin_email,
        credit_logs.user_id,
        users.email AS user_email,
        credit_logs.change_amount,
        credit_logs.reason,
        credit_logs.site_id,
        credit_logs.created_at
      FROM credit_logs
      LEFT JOIN admins ON credit_logs.admin_id = admins.id
      LEFT JOIN users ON credit_logs.user_id = users.id
      WHERE credit_logs.site_id = ?
      ORDER BY credit_logs.id DESC
    `).all(siteId);

    res.json({
      message: "사이트별 이용권 변경 기록 조회 성공",
      siteId,
      total: logs.length,
      logs
    });

  } catch (error) {
    console.error("이용권 기록 조회 오류:", error);

    res.status(500).json({
      message: "이용권 변경 기록을 불러오지 못했습니다."
    });
  }
});


// 통합 관리자 전용 사이트 목록 조회
app.get("/api/admin/sites", verifyAdmin, (req, res) => {
  try {
    const sites = db.prepare(`
      SELECT
        id,
        name,
        slug,
        created_at
      FROM sites
      ORDER BY id ASC
    `).all();

    res.json({
      message: "사이트 목록 조회 성공",
      total: sites.length,
      sites
    });

  } catch (error) {
    console.error("사이트 목록 조회 오류:", error);

    res.status(500).json({
      message: "사이트 목록을 불러오지 못했습니다."
    });
  }
});


// 통합 관리자 전용 사이트 등록
app.post("/api/admin/sites", verifyAdmin, (req, res) => {
  try {
    const { name, slug } = req.body;

    if (!name || !slug) {
      return res.status(400).json({
        message: "사이트 이름과 식별 주소를 입력해 주세요."
      });
    }

    if (!/^[a-z0-9-]+$/.test(slug)) {
      return res.status(400).json({
        message: "식별 주소는 영문 소문자, 숫자, 하이픈만 사용할 수 있습니다."
      });
    }

    const result = db.prepare(`
      INSERT INTO sites (name, slug)
      VALUES (?, ?)
    `).run(name.trim(), slug.trim());

    res.status(201).json({
      message: "사이트 등록 성공",
      siteId: result.lastInsertRowid
    });

  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        message: "이미 등록된 사이트 식별 주소입니다."
      });
    }

    console.error("사이트 등록 오류:", error);

    res.status(500).json({
      message: "사이트 등록에 실패했습니다."
    });
  }
});

// 결제 주문 임시 저장
db.exec(`
  CREATE TABLE IF NOT EXISTS payment_orders (
    order_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    product_type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    credits INTEGER NOT NULL DEFAULT 0,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`NAME-TEC 서버 실행 중: ${PORT}`);
});
