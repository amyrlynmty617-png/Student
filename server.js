import "dotenv/config";
import express from "express";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const port = Number(process.env.PORT) || 3000;

const dbFile = process.env.DB_FILE || "student.sqlite";
const db = new Database(dbFile);

db.pragma("journal_mode = WAL");

/* =========================
   Database
========================= */

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

/* =========================
   Helpers
========================= */

function hash(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function tokenFor(id) {
  const secret = process.env.SESSION_SECRET || "change-this-secret";

  return Buffer.from(
    String(id) + ":" + secret
  ).toString("base64url");
}

function idFromToken(token) {
  try {
    if (!token) return null;

    const secret = process.env.SESSION_SECRET || "change-this-secret";

    const decoded = Buffer.from(
      token,
      "base64url"
    ).toString();

    const separator = decoded.indexOf(":");

    if (separator === -1) {
      return null;
    }

    const id = decoded.slice(0, separator);
    const suppliedSecret = decoded.slice(separator + 1);

    if (suppliedSecret !== secret) {
      return null;
    }

    const numberId = Number(id);

    if (!Number.isInteger(numberId)) {
      return null;
    }

    return numberId;
  } catch {
    return null;
  }
}

/* =========================
   Middleware
========================= */

app.use(
  express.json({
    limit: "10mb"
  })
);

/* فایل‌های سایت */
app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================
   Authentication
========================= */

function auth(req, res, next) {
  const authorization =
    req.headers.authorization || "";

  const token = authorization.replace(
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
    .prepare(
      "SELECT * FROM users WHERE id = ?"
    )
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

/* =========================
   Register
========================= */

app.post(
  "/api/auth/register",
  (req, res) => {
    const {
      name,
      username,
      password,
      grade,
      major
    } = req.body || {};

    if (
      !name ||
      !username ||
      !password ||
      !grade
    ) {
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
          (
            username,
            password_hash,
            name,
            grade,
            major
          )
          VALUES(?,?,?,?,?)
          `
        )
        .run(
          String(username).trim(),
          hash(password),
          String(name).trim(),
          String(grade).trim(),
          major
            ? String(major).trim()
            : ""
        );

      res.json({
        token: tokenFor(
          info.lastInsertRowid
        )
      });
    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(400).json({
        error:
          "این نام کاربری قبلاً ثبت شده است."
      });
    }
  }
);

/* =========================
   Login
========================= */

app.post(
  "/api/auth/login",
  (req, res) => {
    const {
      username,
      password
    } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error:
          "نام کاربری و رمز عبور را وارد کنید."
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
        error:
          "نام کاربری یا رمز عبور اشتباه است."
      });
    }

    if (user.status === "blocked") {
      return res.status(403).json({
        error:
          "این حساب توسط مدیر مسدود شده است."
      });
    }

    res.json({
      token: tokenFor(user.id)
    });
  }
);

/* =========================
   Current User
========================= */

app.get(
  "/api/me",
  auth,
  (req, res) => {
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
  }
);

/* =========================
   Gemini AI
========================= */

app.post(
  "/api/solve",
  auth,
  async (req, res) => {
    try {
      const apiKey =
        process.env.GEMINI_API_KEY;

      if (!apiKey) {
        return res.status(500).json({
          error:
            "GEMINI_API_KEY روی سرور تنظیم نشده است."
        });
      }

      const {
        question = "",
        subject = "سایر",
        level =
          "کامل و مرحله‌به‌مرحله",
        image = null
      } = req.body || {};

      if (!question && !image) {
        return res.status(400).json({
          error:
            "سؤال یا تصویر لازم است."
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

سپس راه‌حل را مرحله‌به‌مرحله،
واضح و آموزشی توضیح بده.

اگر سؤال ناقص یا نامشخص است،
حدس قطعی نزن و اطلاعات موردنیاز
را بگو.
`
        }
      ];

      /* =========================
         Image
      ========================= */

      if (image) {
        if (
          typeof image !== "string" ||
          !/^data:image\/(png|jpe?g|webp|gif);base64,/i.test(
            image
          )
        ) {
          return res.status(400).json({
            error:
              "تصویر معتبر نیست."
          });
        }

        const match = image.match(
          /^data:(image\/(?:png|jpe?g|webp|gif));base64,(.+)$/i
        );

        if (!match) {
          return res.status(400).json({
            error:
              "فرمت تصویر معتبر نیست."
          });
        }

        const mimeType = match[1];
        const base64Data = match[2];

        parts.push({
          inline_data: {
            mime_type: mimeType,
            data: base64Data
          }
        });
      }

      /* =========================
         Gemini Request
      ========================= */

      const model =
        process.env.GEMINI_MODEL ||
        "gemini-2.5-flash";

      const url =
        "https://generativelanguage.googleapis.com/v1beta/models/" +
        encodeURIComponent(model) +
        ":generateContent?key=" +
        encodeURIComponent(apiKey);

      const response = await fetch(
        url,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify({
            contents: [
              {
                parts
              }
            ]
          })
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        console.error(
          "Gemini API error:",
          data
        );

        return res.status(500).json({
          error:
            data?.error?.message ||
            "خطا در ارتباط با Gemini."
        });
      }

      const answer =
        data?.candidates?.[0]?.content?.parts
          ?.map((part) => part.text || "")
          .join("")
          .trim();

      if (!answer) {
        console.error(
          "Empty Gemini response:",
          data
        );

        return res.status(500).json({
          error:
            "پاسخی از Gemini دریافت نشد."
        });
      }

      /* =========================
         Save History
      ========================= */

      db.prepare(
        `
        INSERT INTO analyses
        (
          user_id,
          subject,
          level,
          question,
          answer
        )
        VALUES(?,?,?,?,?)
        `
      ).run(
        req.user.id,
        String(subject),
        String(level),
        String(question || ""),
        answer
      );

      res.json({
        answer
      });
    } catch (error) {
      console.error(
        "Solve error:",
        error
      );

      res.status(500).json({
        error:
          "خطایی هنگام پردازش سؤال رخ داد."
      });
    }
  }
);

/* =========================
   Admin - Users
========================= */

app.get(
  "/api/admin/users",
  auth,
  admin,
  (req, res) => {
    const users = db
      .prepare(
        `
        SELECT
          id,
          username,
          name,
          grade,
          major,
          role,
          status,
          created_at
        FROM users
        ORDER BY id DESC
        `
      )
      .all();

    res.json({
      users
    });
  }
);

/* =========================
   Admin - Block / Unblock
========================= */

app.patch(
  "/api/admin/users/:id/status",
  auth,
  admin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    const status =
      req.body?.status;

    if (
      !Number.isInteger(id) ||
      !["active", "blocked"].includes(
        status
      )
    ) {
      return res.status(400).json({
        error:
          "اطلاعات وضعیت معتبر نیست."
      });
    }

    const result = db
      .prepare(
        `
        UPDATE users
        SET status = ?
        WHERE id = ?
        `
      )
      .run(status, id);

    if (result.changes === 0) {
      return res.status(404).json({
        error:
          "کاربر پیدا نشد."
      });
    }

    res.json({
      success: true
    });
  }
);

/* =========================
   Admin - Delete User
========================= */

app.delete(
  "/api/admin/users/:id",
  auth,
  admin,
  (req, res) => {
    const id = Number(
      req.params.id
    );

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        error:
          "شناسه کاربر معتبر نیست."
      });
    }

    if (id === req.user.id) {
      return res.status(400).json({
        error:
          "مدیر نمی‌تواند خودش را حذف کند."
      });
    }

    db.prepare(
      "DELETE FROM analyses WHERE user_id = ?"
    ).run(id);

    const result = db
      .prepare(
        "DELETE FROM users WHERE id = ?"
      )
      .run(id);

    if (result.changes === 0) {
      return res.status(404).json({
        error:
          "کاربر پیدا نشد."
      });
    }

    res.json({
      success: true
    });
  }
);

/* =========================
   Health Check
========================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "Student"
    });
  }
);

/* =========================
   Website fallback
   بدون app.get("*")
========================= */

app.use(
  (req, res, next) => {
    if (
      req.method !== "GET" ||
      req.path.startsWith("/api/")
    ) {
      return next();
    }

    const indexPath =
      path.join(
        __dirname,
        "public",
        "index.html"
      );

    res.sendFile(
      indexPath,
      (error) => {
        if (error) {
          next();
        }
      }
    );
  }
);

/* =========================
   404
========================= */

app.use(
  (req, res) => {
    res.status(404).json({
      error: "Not found"
    });
  }
);

/* =========================
   Admin Account
========================= */

function createAdmin() {
  const username =
    process.env.ADMIN_USERNAME;

  const password =
    process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    console.log(
      "ADMIN_USERNAME or ADMIN_PASSWORD is not set."
    );

    return;
  }

  const existing = db
    .prepare(
      "SELECT id FROM users WHERE username = ?"
    )
    .get(username);

  if (!existing) {
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
      username,
      hash(password),
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

createAdmin();

/* =========================
   Start Server
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
