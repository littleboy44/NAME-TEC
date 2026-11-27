
import "dotenv/config";
import bcrypt from "bcrypt";
import express from "express";
import cors from "cors";
import db, { initializeDatabase } from "./database.js";
import jwt from "jsonwebtoken";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(cors());
app.use(express.json());

function verifyUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ message: "로그인이 필요합니다." });
    }

    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);

    req.userId = decoded.userId;
    req.siteId = decoded.siteId;
    next();
  } catch {
    return res.status(401).json({ message: "로그인 정보가 유효하지 않습니다." });
  }
}

function verifyAdmin(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ message: "관리자 로그인이 필요합니다." });
    }

    const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({ message: "관리자 권한이 없습니다." });
    }

    req.adminId = decoded.adminId;
    next();
  } catch {
    return res.status(401).json({ message: "인증이 만료되었거나 유효하지 않습니다." });
  }
}


// 토스페이먼츠 결제 승인 및 복구
app.post("/api/payments/confirm", verifyUser, async (req, res) => {
  let client;

  try {
    const { paymentKey, orderId, amount } = req.body;
    const secretKey = process.env.TOSS_SECRET_KEY;

    if (!secretKey) {
      return res.status(500).json({
        message: "결제 서버 설정이 누락되었습니다."
      });
    }

    if (
      typeof paymentKey !== "string" ||
      typeof orderId !== "string" ||
      !Number.isSafeInteger(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        message: "결제 정보가 올바르지 않습니다."
      });
    }

    const authHeader =
      "Basic " + Buffer.from(secretKey + ":").toString("base64");

    // 1. 주문 잠금 및 결제 상태 확인
    client = await db.connect();
    await client.query("BEGIN");

    const orderResult = await client.query(
      `SELECT * FROM payment_orders
       WHERE order_id = $1
       AND user_id = $2
       AND site_id = $3
       FOR UPDATE`,
      [orderId, req.userId, req.siteId]
    );

    const order = orderResult.rows[0];

    if (!order) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        message: "주문 정보를 찾을 수 없습니다."
      });
    }

    if (Number(order.amount) !== amount) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        message: "결제 금액이 주문 정보와 일치하지 않습니다."
      });
    }

    if (order.status === "paid") {
      if (order.payment_key === paymentKey) {
        await client.query("COMMIT");
        return res.json({
          message: "이미 지급 완료된 결제입니다.",
          creditsAdded: 0,
          paymentKey
        });
      }

      await client.query("ROLLBACK");
      return res.status(409).json({
        message: "이미 처리된 주문입니다."
      });
    }

    if (
      order.status === "processing" &&
      order.payment_key !== paymentKey
    ) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        message: "다른 결제가 처리 중인 주문입니다."
      });
    }

    if (order.status === "pending") {
      await client.query(
        `UPDATE payment_orders
         SET status = 'processing',
             payment_key = $1
         WHERE order_id = $2`,
        [paymentKey, orderId]
      );
    } else if (order.status !== "processing") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        message: "유효하지 않은 주문 상태입니다."
      });
    }

    await client.query("COMMIT");
    client.release();
    client = null;

    // 2. 토스 결제 승인 요청
    let tossData = null;
    let tossResponse = null;

    try {
      tossResponse = await fetch(
        "https://api.tosspayments.com/v1/payments/confirm",
        {
          method: "POST",
          headers: {
            Authorization: authHeader,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            paymentKey,
            orderId,
            amount
          })
        }
      );

      tossData = await tossResponse.json();
    } catch (error) {
      console.error("토스 승인 요청 통신 오류:", error);
    }

    // 3. 승인 요청이 실패하거나 응답이 불확실하면 결제 조회
    if (
      !tossResponse ||
      !tossResponse.ok ||
      !tossData ||
      tossData.status !== "DONE"
    ) {
      try {
        const lookupResponse = await fetch(
          `https://api.tosspayments.com/v1/payments/${encodeURIComponent(paymentKey)}`,
          {
            method: "GET",
            headers: {
              Authorization: authHeader
            }
          }
        );

        const lookupData = await lookupResponse.json();

        if (lookupResponse.ok) {
          tossData = lookupData;
        } else {
          console.error("토스 결제 조회 실패:", lookupData);
          return res.status(502).json({
            message: "결제 상태를 확인할 수 없습니다. 잠시 후 다시 시도해 주세요."
          });
        }
      } catch (error) {
        console.error("토스 결제 조회 통신 오류:", error);
        return res.status(502).json({
          message: "결제 상태 확인에 실패했습니다. 잠시 후 다시 시도해 주세요."
        });
      }
    }

// 4. 토스 승인 정보 검증
if (
  !tossData ||
  tossData.orderId !== orderId ||
  Number(tossData.totalAmount) !== amount ||
  tossData.paymentKey !== paymentKey
) {
  return res.status(400).json({
    message: "결제 승인 정보 검증에 실패했습니다."
  });
}

// 결제 완료가 아닌 경우
if (tossData.status !== "DONE") {
  console.error("토스 결제 미완료:", tossData.status);

  // 취소 또는 승인 거절 등 확실한 실패 상태만 주문 실패 처리
  if (["CANCELED", "ABORTED", "EXPIRED"].includes(tossData.status)) {
    const failClient = await db.connect();

    try {
      await failClient.query("BEGIN");

      await failClient.query(
        `UPDATE payment_orders
         SET status = 'failed',
             payment_key = NULL
         WHERE order_id = $1
           AND user_id = $2
           AND site_id = $3
           AND status = 'processing'
           AND payment_key = $4`,
        [orderId, req.userId, req.siteId, paymentKey]
      );

      await failClient.query("COMMIT");
    } catch (error) {
      await failClient.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      failClient.release();
    }
  }

  return res.status(409).json({
    message: "결제가 완료되지 않았습니다. 결제 상태를 확인해 주세요."
  });
}

// 5번 DB 트랜잭션으로 이어짐

    // 5. DB 트랜잭션으로 이용권 중복 지급 방지
    client = await db.connect();
    await client.query("BEGIN");

    const lockedOrder = await client.query(
      `SELECT * FROM payment_orders
       WHERE order_id = $1
       AND user_id = $2
       AND site_id = $3
       FOR UPDATE`,
      [orderId, req.userId, req.siteId]
    );

    const currentOrder = lockedOrder.rows[0];

    if (!currentOrder) {
      throw new Error("주문 정보를 다시 확인할 수 없습니다.");
    }

    if (currentOrder.status === "paid") {
      if (currentOrder.payment_key === paymentKey) {
        await client.query("COMMIT");
        client.release();
        client = null;

        return res.json({
          message: "이미 지급 완료된 결제입니다.",
          creditsAdded: 0,
          paymentKey
        });
      }

      throw new Error("다른 결제가 이미 처리된 주문입니다.");
    }

    if (
      currentOrder.status !== "processing" ||
      currentOrder.payment_key !== paymentKey
    ) {
      throw new Error("주문 상태가 일치하지 않습니다.");
    }
const paymentInsert = await client.query(
  `INSERT INTO payments
   (user_id, payment_id, amount, product_type, status, site_id)
   VALUES ($1, $2, $3, $4, 'DONE', $5)
   ON CONFLICT (payment_id) DO NOTHING
   RETURNING id`,
  [
    req.userId,
    paymentKey,
    amount,
    currentOrder.product_type,
    req.siteId
  ]
);

if (paymentInsert.rows.length !== 1) {
  throw new Error("이미 다른 주문에 사용된 결제 키입니다.");
}

const userUpdate = await client.query(
      `UPDATE users
       SET credits = credits + $1
       WHERE id = $2 AND site_id = $3`,
      [
        currentOrder.credits,
        req.userId,
        req.siteId
      ]
    );

    if (userUpdate.rowCount !== 1) {
      throw new Error("이용권 지급 대상 회원을 찾을 수 없습니다.");
    }

    await client.query(
      `UPDATE payment_orders
       SET status = 'paid',
           approved_at = CURRENT_TIMESTAMP
       WHERE order_id = $1`,
      [orderId]
    );

    await client.query("COMMIT");

    return res.json({
      message: "결제가 완료되었습니다.",
      creditsAdded: currentOrder.credits,
      paymentKey
    });

  } catch (error) {
    if (client) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("결제 승인 처리 오류:", error);

    return res.status(500).json({
      message: "결제 승인 처리 중 오류가 발생했습니다. 결제 상태를 확인해 주세요."
    });

  } finally {
    client?.release();
  }
});

// 회원가입
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

    const normalizedEmail = email.trim().toLowerCase();

    const siteResult = await db.query(
      "SELECT id FROM sites WHERE slug = $1",
      ["name-tec"]
    );

    const site = siteResult.rows[0];

    if (!site) {
      return res.status(500).json({ message: "사이트 정보를 찾을 수 없습니다." });
    }

    const existing = await db.query(
      "SELECT id FROM users WHERE email = $1 AND site_id = $2",
      [normalizedEmail, site.id]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "이미 가입된 이메일입니다." });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(`
      INSERT INTO users (email, password_hash, site_id)
      VALUES ($1, $2, $3)
      RETURNING id
    `, [normalizedEmail, passwordHash, site.id]);

    const token = jwt.sign(
      { userId: Number(result.rows[0].id), siteId: Number(site.id) },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({ message: "회원가입 성공", token });
  } catch (error) {
    console.error("회원가입 오류:", error);
    res.status(500).json({ message: "회원가입에 실패했습니다." });
  }
});

// 회원 로그인
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({ message: "이메일과 비밀번호를 입력해 주세요." });
    }

    const siteResult = await db.query(
      "SELECT id FROM sites WHERE slug = $1",
      ["name-tec"]
    );

    const site = siteResult.rows[0];

    if (!site) {
      return res.status(500).json({ message: "사이트 정보를 찾을 수 없습니다." });
    }

    const result = await db.query(`
      SELECT id, email, password_hash, credits
      FROM users
      WHERE email = $1 AND site_id = $2
    `, [email.trim().toLowerCase(), site.id]);

    const user = result.rows[0];

    if (!user || !user.password_hash) {
      return res.status(401).json({
        message: "이메일 또는 비밀번호가 올바르지 않습니다."
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({
        message: "이메일 또는 비밀번호가 올바르지 않습니다."
      });
    }

    const token = jwt.sign(
      { userId: Number(user.id), siteId: Number(site.id) },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "로그인 성공",
      token,
      user: {
        id: Number(user.id),
        email: user.email,
        credits: user.credits
      }
    });
  } catch (error) {
    console.error("로그인 오류:", error);
    res.status(500).json({ message: "로그인에 실패했습니다." });
  }
});


// 토스 결제 클라이언트 키 제공
app.get("/api/payments/config", (req, res) => {
  const clientKey = process.env.TOSS_CLIENT_KEY;

  if (!clientKey) {
    return res.status(500).json({
      message: "결제 설정이 누락되었습니다."
    });
  }

  res.json({ clientKey });
});


// 결제 주문 생성
app.post("/api/payments/create-order", verifyUser, async (req, res) => {
  try {
const products = {
  PLUS: {
    name: "NAME-TEC PLUS",
    amount: 990,
    credits: 3
  },
  PREMIUM: {
    name: "NAME-TEC PREMIUM",
    amount: 2900,
    credits: 10
  }
};

    const product = products[req.body.productType];

    if (!product) {
      return res.status(400).json({ message: "올바르지 않은 상품입니다." });
    }

    const orderId = randomUUID();

    await db.query(`
      INSERT INTO payment_orders
      (order_id, user_id, site_id, product_type, amount, credits)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [
  orderId,
  req.userId,
  req.siteId,
  req.body.productType,
  product.amount,
  product.credits
]);

    res.status(201).json({
      message: "결제 주문 생성 성공",
      orderId,
      orderName: product.name,
      amount: product.amount
    });
  } catch (error) {
    console.error("결제 주문 생성 오류:", error);
    res.status(500).json({ message: "결제 주문 생성에 실패했습니다." });
  }
});

// 관리자 페이지
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// 서버 상태 확인
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "NAME-TEC 서버가 준비되었습니다." });
});

// 데이터베이스 상태 확인
app.get("/api/db-health", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ status: "ok", message: "PostgreSQL 연결 정상" });
  } catch (error) {
    console.error("DB 상태 확인 오류:", error);
    res.status(500).json({ status: "error" });
  }
});


// 관리자 로그인
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "이메일과 비밀번호를 입력해 주세요."
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const allowedEmail = String(ADMIN_EMAIL).trim().toLowerCase();

    // 환경변수에 등록된 관리자 이메일만 허용
    if (normalizedEmail !== allowedEmail) {
      return res.status(401).json({
        message: "로그인 정보가 올바르지 않습니다."
      });
    }

    const result = await db.query(
      "SELECT * FROM admins WHERE LOWER(email) = $1",
      [normalizedEmail]
    );

    const admin = result.rows[0];

    if (!admin || !(await bcrypt.compare(password, admin.password_hash))) {
      return res.status(401).json({
        message: "로그인 정보가 올바르지 않습니다."
      });
    }

    const token = jwt.sign(
      { adminId: Number(admin.id), role: "admin" },
      JWT_SECRET,
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


// 전체 대시보드
app.get("/api/admin/dashboard", verifyAdmin, async (req, res) => {
  try {
    const adminResult = await db.query(
      "SELECT id, email, created_at FROM admins WHERE id = $1",
      [req.adminId]
    );

    const [members, payments, logs, sites] = await Promise.all([
      db.query("SELECT COUNT(*) AS count FROM users"),
      db.query("SELECT COUNT(*) AS count FROM payments"),
      db.query("SELECT COUNT(*) AS count FROM credit_logs"),
      db.query("SELECT COUNT(*) AS count FROM sites")
    ]);

    res.json({
      message: "관리자 인증 및 전체 통계 조회 성공",
      admin: adminResult.rows[0],
      stats: {
        totalMembers: Number(members.rows[0].count),
        totalPayments: Number(payments.rows[0].count),
        totalCreditLogs: Number(logs.rows[0].count),
        totalSites: Number(sites.rows[0].count)
      }
    });
  } catch (error) {
    console.error("대시보드 조회 오류:", error);
    res.status(500).json({ message: "대시보드 정보를 불러오지 못했습니다." });
  }
});

// 사이트별 회원 조회
app.get("/api/admin/members", verifyAdmin, async (req, res) => {
  try {
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({ message: "올바른 사이트 번호를 입력해 주세요." });
    }

    const result = await db.query(`
      SELECT id, email, credits, premium_until, created_at
      FROM users
      WHERE site_id = $1
      ORDER BY id DESC
    `, [siteId]);

    res.json({
      message: "사이트별 회원 목록 조회 성공",
      siteId,
      total: result.rows.length,
      members: result.rows
    });
  } catch (error) {
    console.error("회원 조회 오류:", error);
    res.status(500).json({ message: "회원 목록을 불러오지 못했습니다." });
  }
});

// 사이트별 결제 내역
app.get("/api/admin/payments", verifyAdmin, async (req, res) => {
  try {
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({ message: "올바른 사이트 번호를 입력해 주세요." });
    }

    const result = await db.query(`
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
      WHERE payments.site_id = $1
      ORDER BY payments.id DESC
    `, [siteId]);

    res.json({
      message: "사이트별 결제 내역 조회 성공",
      siteId,
      total: result.rows.length,
      payments: result.rows
    });
  } catch (error) {
    console.error("결제 조회 오류:", error);
    res.status(500).json({ message: "결제 내역을 불러오지 못했습니다." });
  }
});

// 회원 상세 조회
app.get("/api/admin/members/:id", verifyAdmin, async (req, res) => {
  try {
    const memberId = Number(req.params.id);
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(memberId) || memberId <= 0 ||
        !Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({ message: "회원 번호 또는 사이트 번호가 올바르지 않습니다." });
    }

    const memberResult = await db.query(`
      SELECT id, email, credits, premium_until, created_at
      FROM users
      WHERE id = $1 AND site_id = $2
    `, [memberId, siteId]);

    const member = memberResult.rows[0];

    if (!member) {
      return res.status(404).json({ message: "해당 사이트에서 회원을 찾을 수 없습니다." });
    }

    const payments = await db.query(`
      SELECT payment_id, amount, product_type, status, created_at
      FROM payments
      WHERE user_id = $1 AND site_id = $2
      ORDER BY id DESC
    `, [memberId, siteId]);

    res.json({
      message: "회원 상세 조회 성공",
      member,
      payments: payments.rows
    });
  } catch (error) {
    console.error("회원 상세 조회 오류:", error);
    res.status(500).json({ message: "회원 정보를 불러오지 못했습니다." });
  }
});

// 이용권 지급 및 차감
app.post("/api/admin/members/:id/credits", verifyAdmin, async (req, res) => {
  const client = await db.connect();

  try {
    const memberId = Number(req.params.id);
    const siteId = Number(req.query.siteId);
    const { amount, reason } = req.body;

    if (!Number.isInteger(memberId) || memberId <= 0 ||
        !Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({ message: "회원 번호 또는 사이트 번호가 올바르지 않습니다." });
    }

    if (!Number.isInteger(amount) || amount === 0 || Math.abs(amount) > 1000) {
      return res.status(400).json({
        message: "변경 횟수는 -1000부터 1000 사이의 0이 아닌 정수여야 합니다."
      });
    }

    if (typeof reason !== "string" || !reason.trim() || reason.length > 200) {
      return res.status(400).json({ message: "변경 사유를 1~200자로 입력해 주세요." });
    }

    await client.query("BEGIN");

    const memberResult = await client.query(
      "SELECT id, credits FROM users WHERE id = $1 AND site_id = $2 FOR UPDATE",
      [memberId, siteId]
    );

    const member = memberResult.rows[0];

    if (!member) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "해당 사이트에서 회원을 찾을 수 없습니다." });
    }

    if (member.credits + amount < 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "이용권 잔액보다 많이 차감할 수 없습니다." });
    }

    await client.query(
      "UPDATE users SET credits = credits + $1 WHERE id = $2 AND site_id = $3",
      [amount, memberId, siteId]
    );

    await client.query(`
      INSERT INTO credit_logs
      (admin_id, user_id, change_amount, reason, site_id)
      VALUES ($1, $2, $3, $4, $5)
    `, [req.adminId, memberId, amount, reason.trim(), siteId]);

    await client.query("COMMIT");

    const updated = await db.query(
      "SELECT id, email, credits FROM users WHERE id = $1 AND site_id = $2",
      [memberId, siteId]
    );

    res.json({ message: "이용권 변경 성공", member: updated.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("이용권 변경 오류:", error);
    res.status(500).json({ message: "이용권 변경에 실패했습니다." });
  } finally {
    client.release();
  }
});

// 이용권 변경 기록
app.get("/api/admin/credit-logs", verifyAdmin, async (req, res) => {
  try {
    const siteId = Number(req.query.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({ message: "올바른 사이트 번호를 입력해 주세요." });
    }

    const result = await db.query(`
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
      WHERE credit_logs.site_id = $1
      ORDER BY credit_logs.id DESC
    `, [siteId]);

    res.json({
      message: "사이트별 이용권 변경 기록 조회 성공",
      siteId,
      total: result.rows.length,
      logs: result.rows
    });
  } catch (error) {
    console.error("이용권 기록 조회 오류:", error);
    res.status(500).json({ message: "이용권 변경 기록을 불러오지 못했습니다." });
  }
});

// 회원 프리미엄 이용권 1회 사용
app.post("/api/credits/use", verifyUser, async (req, res) => {
  const client = await db.connect();

  try {
    const userId = req.userId;
    const siteId = Number(req.siteId);

    if (!Number.isInteger(siteId) || siteId <= 0) {
      return res.status(400).json({ message: "사이트 정보가 올바르지 않습니다." });
    }

    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, credits
       FROM users
       WHERE id = $1 AND site_id = $2
       FOR UPDATE`,
      [userId, siteId]
    );

    const user = result.rows[0];

    if (!user) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "회원을 찾을 수 없습니다." });
    }

    if (user.credits < 1) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "이용권이 부족합니다." });
    }

    await client.query(
      `UPDATE users
       SET credits = credits - 1
       WHERE id = $1 AND site_id = $2`,
      [userId, siteId]
    );

    await client.query(
      `INSERT INTO credit_logs
       (admin_id, user_id, change_amount, reason, site_id)
       VALUES (NULL, $1, -1, $2, $3)`,
      [userId, "프리미엄 이름 생성", siteId]
    );

    await client.query("COMMIT");

    const updated = await client.query(
      "SELECT credits FROM users WHERE id = $1 AND site_id = $2",
      [userId, siteId]
    );

    return res.json({
      message: "이용권 1회 사용 완료",
      credits: updated.rows[0].credits
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("이용권 사용 오류:", error);
    return res.status(500).json({ message: "이용권 사용에 실패했습니다." });
  } finally {
    client.release();
  }
});

// 사이트 목록
app.get("/api/admin/sites", verifyAdmin, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, name, slug, created_at
      FROM sites
      ORDER BY id ASC
    `);

    res.json({
      message: "사이트 목록 조회 성공",
      total: result.rows.length,
      sites: result.rows
    });
  } catch (error) {
    console.error("사이트 목록 조회 오류:", error);
    res.status(500).json({ message: "사이트 목록을 불러오지 못했습니다." });
  }
});

// 사이트 등록
app.post("/api/admin/sites", verifyAdmin, async (req, res) => {
  try {
    const { name, slug } = req.body;

    if (typeof name !== "string" || !name.trim() ||
        typeof slug !== "string" || !slug.trim()) {
      return res.status(400).json({ message: "사이트 이름과 식별 주소를 입력해 주세요." });
    }

    if (!/^[a-z0-9-]+$/.test(slug)) {
      return res.status(400).json({
        message: "식별 주소는 영문 소문자, 숫자, 하이픈만 사용할 수 있습니다."
      });
    }

    const result = await db.query(`
      INSERT INTO sites (name, slug)
      VALUES ($1, $2)
      RETURNING id
    `, [name.trim(), slug.trim()]);

    res.status(201).json({
      message: "사이트 등록 성공",
      siteId: Number(result.rows[0].id)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "이미 등록된 사이트 식별 주소입니다." });
    }

    console.error("사이트 등록 오류:", error);
    res.status(500).json({ message: "사이트 등록에 실패했습니다." });
  }
});

// 서버 시작
async function startServer() {
  try {
    if (!JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
      throw new Error("JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD 환경변수를 확인해 주세요.");
    }

    await initializeDatabase();

    const existingAdmin = await db.query(
      "SELECT id FROM admins WHERE email = $1",
      [ADMIN_EMAIL]
    );

    if (existingAdmin.rows.length === 0) {
      const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

      await db.query(
        "INSERT INTO admins (email, password_hash) VALUES ($1, $2)",
        [ADMIN_EMAIL, passwordHash]
      );

      console.log("관리자 계정 등록 완료!");
    }

    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
      console.log(`NAME-TEC 서버 실행 중: ${PORT}`);
    });
  } catch (error) {
    console.error("서버 시작 실패:", error);
    process.exit(1);
  }
}

startServer();
