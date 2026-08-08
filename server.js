const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json());
app.use(cookieParser());

function auth(req, res, next) {
  const token = req.cookies.workdesk_token;

  if (!token) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  try {
    req.user = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
      error: "Invalid session"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "Admin") {
    return res.status(403).json({
      error: "Admin only"
    });
  }

  next();
}


/* LOGIN */

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1)",
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "8h"
      }
    );

    res.cookie(
      "workdesk_token",
      token,
      {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax"
      }
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Server error"
    });
  }
});


/* LOGOUT */

app.post("/api/logout", (req, res) => {
  res.clearCookie("workdesk_token");

  res.json({
    success: true
  });
});


/* CURRENT USER */

app.get("/api/me", auth, async (req, res) => {

  const result = await pool.query(
    "SELECT id,name,email,role FROM users WHERE id=$1",
    [req.user.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      error: "User not found"
    });
  }

  res.json({
    user: result.rows[0]
  });
});


/* USERS */

app.get("/api/users", auth, adminOnly, async (req, res) => {

  const result = await pool.query(`
    SELECT id,name,email,role,created_at
    FROM users
    ORDER BY id DESC
  `);

  res.json(result.rows);
});


/* CREATE USER */

app.post("/api/users", auth, adminOnly, async (req, res) => {

  try {

    const {
      name,
      email,
      password,
      role = "User"
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "All fields are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters"
      });
    }

    const hash = await bcrypt.hash(
      password,
      12
    );

    const result = await pool.query(`
      INSERT INTO users
      (name,email,password,role)
      VALUES ($1,$2,$3,$4)
      RETURNING id,name,email,role
    `, [
      name,
      email.toLowerCase(),
      hash,
      role
    ]);

    res.json(result.rows[0]);

  } catch (error) {

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Email already exists"
      });
    }

    console.error(error);

    res.status(500).json({
      error: "Could not create user"
    });
  }
});


/* DELETE USER */

app.delete(
  "/api/users/:id",
  auth,
  adminOnly,
  async (req, res) => {

    const id = Number(req.params.id);

    if (id === req.user.id) {
      return res.status(400).json({
        error: "You cannot delete yourself"
      });
    }

    await pool.query(
      "DELETE FROM users WHERE id=$1",
      [id]
    );

    res.json({
      success: true
    });
  }
);


/* ALL TICKETS */

app.get("/api/tickets", auth, async (req, res) => {

  const result = await pool.query(`
    SELECT
      t.*,
      r.name AS requester_name,
      a.name AS assignee_name
    FROM tickets t

    LEFT JOIN users r
      ON t.requester_id = r.id

    LEFT JOIN users a
      ON t.assignee_id = a.id

    ORDER BY t.id DESC
  `);

  res.json(result.rows);
});


/* CREATE TICKET */

app.post("/api/tickets", auth, async (req, res) => {

  try {

    const {
      subject,
      problem,
      department = "IT",
      priority = "Medium",
      assignee_id = null
    } = req.body;

    if (!subject || !problem) {
      return res.status(400).json({
        error: "Subject and problem are required"
      });
    }

    const result = await pool.query(`
      INSERT INTO tickets
      (
        requester_id,
        subject,
        problem,
        department,
        priority,
        status,
        assignee_id
      )

      VALUES
      ($1,$2,$3,$4,$5,'Open',$6)

      RETURNING *
    `, [
      req.user.id,
      subject,
      problem,
      department,
      priority,
      assignee_id
    ]);

    res.status(201).json(
      result.rows[0]
    );

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Could not create ticket"
    });
  }
});


/* UPDATE TICKET */

app.put("/api/tickets/:id", auth, async (req, res) => {

  const id = Number(req.params.id);

  const {
    status,
    priority,
    assignee_id
  } = req.body;

  const result = await pool.query(`
    UPDATE tickets

    SET
      status = COALESCE($1,status),
      priority = COALESCE($2,priority),
      assignee_id = COALESCE($3,assignee_id)

    WHERE id=$4

    RETURNING *
  `, [
    status,
    priority,
    assignee_id,
    id
  ]);

  if (!result.rows.length) {
    return res.status(404).json({
      error: "Ticket not found"
    });
  }

  res.json(result.rows[0]);
});


/* DELETE TICKET */

app.delete(
  "/api/tickets/:id",
  auth,
  adminOnly,
  async (req, res) => {

    await pool.query(
      "DELETE FROM tickets WHERE id=$1",
      [Number(req.params.id)]
    );

    res.json({
      success: true
    });
  }
);


/* START SERVER */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `WorkDesk backend running on port ${PORT}`
    );
  }
);
