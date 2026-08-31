import "dotenv/config";
import express from "express";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

const db = new Database(process.env.DB_FILE || "student.sqlite");
db.pragma("journal_mode = WAL");

try {
  db.exec(
    "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
  );
} catch {}

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  grade TEXT NOT NULL,
  major TEXT,
  role TEXT NOT NULL DEFAULT 'student',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analyses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  level TEXT NOT NULL,
  question TEXT,
  answer TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function hash(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function tokenFor(id) {
  return Buffer.from(
    String(id) + ":" + process.env.SESSION_SECRET
  ).toString("base64url");
}

function idFromToken(token) {
  try {
    const decoded = Buffer.from(token, "base64url").toString();
    const separator = decoded.indexOf(":");

    if (separator === -1) return null;

    const id = decoded.slice(0, separator);
    const secret = decoded.slice(separator + 1);

    if (secret !== process.env.SESSION_SECRET) return null;

    const numberId = Number(id);
    return Number.isInteger(numberId) ? numberId : null;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(
    /^Bearer\s+/i,
    ""
  );

  const id = idFromToken(token);

  if (!id) {
    return res.status(401).json({
      error: "ورود لازم است."
    });
  }

  const user = db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(id);

  if (!user) {
    return res.status(401).json({
      error: "حساب پیدا نشد."
    });
  }

  if (user.status === "blocked") {
    return res.status(403).json({
      error: "این حساب مسدود شده است."
    });
  }

  req.user = user;
  next();
}

function admin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "دسترسی مدیر لازم است."
    });
  }

  next();
}

app.use(
  express.json({
    limit: "10mb"
  })
);

/* فایل‌های سایت */
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   ثبت نام
========================= */

app.post("/api/auth/register", (req, res) => {
  const {
    name,
    username,
    password,
    grade,
    major
  } = req.body || {};

  if (!name || !username || !password || !grade) {
    return res.status(400).json({
      error: "اطلاعات ضروری کامل نیست."
    });
  }

  if (String(password).length < 4) {
    return res.status(400).json({
      error: "رمز حداقل ۴ کاراکتر باشد."
    });
  }

  try {
    const info = db
      .prepare(
        `
        INSERT INTO users
        (username,password_hash,name,grade,major)
        VALUES(?,?,?,?,?)
        `
      )
      .run(
        String(username).trim(),
        hash(password),
        String(name).trim(),
        String(grade).trim(),
        major ? String(major).trim() : ""
      );

    res.json({
      token: tokenFor(info.lastInsertRowid)
    });
  } catch (error) {
    console.error(error);

    res.status(400).json({
      error: "این نام کاربری قبلاً ثبت شده است."
    });
  }
});

/* =========================
   ورود
========================= */

app.post("/api/auth/login", (req, res) => {
  const {
    username,
    password
  } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "نام کاربری و رمز عبور را وارد کنید."
    });
  }

  const user = db
    .prepare(
      `
      SELECT *
      FROM users
      WHERE username = ?
      AND password_hash = ?
      `
    )
    .get(
      String(username).trim(),
      hash(password)
    );

  if (!user) {
    return res.status(401).json({
      error: "نام کاربری یا رمز عبور اشتباه است."
    });
  }

  if (user.status === "blocked") {
    return res.status(403).json({
      error: "این حساب توسط مدیر مسدود شده است."
    });
  }

  res.json({
    token: tokenFor(user.id)
  });
});

/* =========================
   اطلاعات کاربر
========================= */

app.get("/api/me", auth, (req, res) => {
  const history = db
    .prepare(
      `
      SELECT
        id,
        subject,
        level,
        question,
        answer,
        created_at AS date
      FROM analyses
      WHERE user_id = ?
      ORDER BY id DESC
      `
    )
    .all(req.user.id);

  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      name: req.user.name,
      grade: req.user.grade,
      major: req.user.major,
      role: req.user.role,
      history
    }
  });
});

/* =========================
   Gemini AI
========================= */

app.post("/api/solve", auth, async (req, res) => {
  try {
    if (!process.env.GEMINI_API_KEY) {
      return res.status(500).json({
        error: "GEMINI_API_KEY روی سرور تنظیم نشده است."
      });
    }

    const {
      question = "",
      subject = "سایر",
      level = "کامل و مرحله‌به‌مرحله",
      image = null
    } = req.body || {};

    if (!question && !image) {
      return res.status(400).json({
        error: "سؤال یا تصویر لازم است."
      });
    }

    const parts = [
      {
        text: `
تو معلم خصوصی دانش‌آموز هستی.

پایه دانش‌آموز:
${req.user.grade}

رشته:
${req.user.major || "نامشخص"}

درس:
${subject}

سطح توضیح:
${level}

سؤال:
${question || "سؤال در تصویر قرار دارد."}

به فارسی پاسخ بده.

ابتدا پاسخ نهایی را مشخص کن.
سپس راه‌حل را مرحله‌به‌مرحله و آموزشی توضیح بده.
اگر سؤال ناقص یا نامشخص است، حدس قطعی نزن و اطلاعات موردنیاز را بگو.
`
      }
    ];

    /* اگر تصویر ارسال شده باشد */
    if (image) {
      if (
        typeof image !== "string" ||
        !/^data:image\/(png|jpe?g|webp|gif);base64,/i.test(image)
      ) {
        return res.status(400).json({
          error: "تصویر معتبر نیست."
        });
      }

      const match = image.match(
        /^data:(image\/(?:png|jpe?g|webp|gif));base64,(.+)$/i
      );

      if (!match) {
        return res.status(400).json({
          error: "تصویر معتبر نیست."
        });
      }

      parts.push({
        inlineData: {
          mimeType: match[1],
          data: match[2]
        }
      });
    }

    const model =
      process.env.GEMINI_MODEL || "gemini-3.7-flash";

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
        model
      )}:generateContent`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": process.env.GEMINI_API_KEY
        },

        body: JSON.stringify({
          contents: [
            {
              role: "user",
              parts
            }
          ],

          generationConfig: {
            temperature: 0.4,
            maxOutputTokens: 4096
          }
        })
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      console.error(
        "Gemini API error:",
        response.status,
        data
      );

      const detail =
        data?.error?.message ||
        "خطا از طرف Gemini";

      return res.status(502).json({
        error:
          "ارتباط با Gemini ناموفق بود: " +
          detail
      });
    }

    const answer =
      data?.candidates?.[0]?.content?.parts
        ?.map((part) => part.text || "")
        .join("")
        .trim() || "";

    if (!answer) {
      return res.status(502).json({
        error:
          "Gemini پاسخ متنی قابل نمایش برنگرداند."
      });
    }

    const info = db
      .prepare(
        `
        INSERT INTO analyses
        (user_id,subject,level,question,answer)
        VALUES(?,?,?,?,?)
        `
      )
      .run(
        req.user.id,
        subject,
        level,
        question,
        answer
      );

    res.json({
      id: info.lastInsertRowid,
      answer,
      date: new Date().toLocaleString("fa-IR")
    });
  } catch (error) {
    console.error(
      "AI error:",
      error
    );

    res.status(500).json({
      error: "خطا در ارتباط با هوش مصنوعی."
    });
  }
});

/* =========================
   آمار مدیر
========================= */

app.get(
  "/api/admin/stats",
  auth,
  admin,
  (req, res) => {
    const totalUsers = db
      .prepare(
        "SELECT COUNT(*) AS c FROM users"
      )
      .get().c;

    const activeUsers = db
      .prepare(
        "SELECT COUNT(*) AS c FROM users WHERE status='active'"
      )
      .get().c;

    const blockedUsers = db
      .prepare(
        "SELECT COUNT(*) AS c FROM users WHERE status='blocked'"
      )
      .get().c;

    const totalAnalyses = db
      .prepare(
        "SELECT COUNT(*) AS c FROM analyses"
      )
      .get().c;

    const todayAnalyses = db
      .prepare(
        `
        SELECT COUNT(*) AS c
        FROM analyses
        WHERE date(created_at)=date('now')
        `
      )
      .get().c;

    const subjects = db
      .prepare(
        `
        SELECT subject, COUNT(*) AS count
        FROM analyses
        GROUP BY subject
        ORDER BY count DESC
        `
      )
      .all();

    res.json({
      totalUsers,
      activeUsers,
      blockedUsers,
      totalAnalyses,
      todayAnalyses,
      subjects
    });
  }
);

/* =========================
   کاربران مدیر
========================= */

app.get(
  "/api/admin/users",
  auth,
  admin,
  (req, res) => {
    const q = String(
      req.query.q || ""
    ).trim();

    const users = db
      .prepare(
        `
        SELECT
          u.id,
          u.username,
          u.name,
          u.grade,
          u.major,
          u.role,
          u.status,
          u.created_at,

          (
            SELECT COUNT(*)
            FROM analyses a
            WHERE a.user_id = u.id
          ) AS historyCount

        FROM users u

        WHERE
          (
            ? = ''
            OR u.username LIKE '%' || ? || '%'
            OR u.name LIKE '%' || ? || '%'
          )

        ORDER BY u.id DESC
        `
      )
      .all(q, q, q);

    res.json({
      users
    });
  }
);

/* =========================
   تحلیل‌های مدیر
========================= */

app.get(
  "/api/admin/analyses",
  auth,
  admin,
  (req, res) => {
    const analyses = db
      .prepare(
        `
        SELECT
          a.id,
          a.subject,
          a.level,
          a.question,
          a.answer,
          a.created_at,
          u.username,
          u.name

        FROM analyses a

        JOIN users u
        ON u.id = a.user_id

        ORDER BY a.id DESC

        LIMIT 300
        `
      )
      .all();

    res.json({
      analyses
    });
  }
);

/* =========================
   مسدود کردن کاربر
========================= */

app.post(
  "/api/admin/users/:id/block",
  auth,
  admin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    if (id === req.user.id) {
      return res.status(400).json({
        error:
          "نمی‌توانی حساب مدیر فعلی را مسدود کنی."
      });
    }

    db.prepare(
      "UPDATE users SET status='blocked' WHERE id=?"
    ).run(id);

    res.json({
      ok: true
    });
  }
);

/* =========================
   رفع مسدودی
========================= */

app.post(
  "/api/admin/users/:id/unblock",
  auth,
  admin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    db.prepare(
      "UPDATE users SET status='active' WHERE id=?"
    ).run(id);

    res.json({
      ok: true
    });
  }
);

/* =========================
   حذف کاربر
========================= */

app.delete(
  "/api/admin/users/:id",
  auth,
  admin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    if (id === req.user.id) {
      return res.status(400).json({
        error:
          "نمی‌توانی حساب خودت را حذف کنی."
      });
    }

    db.prepare(
      "DELETE FROM analyses WHERE user_id=?"
    ).run(id);

    db.prepare(
      "DELETE FROM users WHERE id=?"
    ).run(id);

    res.json({
      ok: true
    });
  }
);

/* =========================
   حذف تحلیل
========================= */

app.delete(
  "/api/admin/analyses/:id",
  auth,
  admin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    db.prepare(
      "DELETE FROM analyses WHERE id=?"
    ).run(id);

    res.json({
      ok: true
    });
  }
);

/* =========================
   صفحه اصلی
========================= */

/*
  اینجا عمداً از app.get("*")
  استفاده نشده است.
  چون Express 5 و path-to-regexp
  با wildcard بدون نام پارامتر مشکل دارند.
*/

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/*
  برای مسیرهای عادی سایت هم
  index.html نمایش داده می‌شود،
  ولی APIها دست‌نخورده باقی می‌مانند.
*/

app.use((req, res, next) => {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api/")
  ) {
    return res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }

  next();
});

/* =========================
   ساخت ادمین
========================= */

if (
  process.env.ADMIN_USERNAME &&
  process.env.ADMIN_PASSWORD
) {
  const exists = db
    .prepare(
      "SELECT id FROM users WHERE username=?"
    )
    .get(
      process.env.ADMIN_USERNAME
    );

  if (!exists) {
    db.prepare(
      `
      INSERT INTO users
      (
        username,
        password_hash,
        name,
        grade,
        major,
        role,
        status
      )
      VALUES(?,?,?,?,?,?,?)
      `
    ).run(
      process.env.ADMIN_USERNAME,
      hash(process.env.ADMIN_PASSWORD),
      "مدیر سیستم",
      "مدیر",
      "",
      "admin",
      "active"
    );

    console.log(
      "Admin account created."
    );
  }
}

/* =========================
   اجرای سرور
========================= */

app.listen(
  port,
  "0.0.0.0",
  () => {
    console.log(
      `Server running on port ${port}`
    );
  }
);
