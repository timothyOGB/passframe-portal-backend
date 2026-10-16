import { Hono } from "hono";
import { hashPin, randomSalt, createSessionToken, verifySessionToken } from "./auth.js";

const app = new Hono();

// ---------- helpers ----------

function newId() {
  return crypto.randomUUID();
}

function userPublic(row) {
  if (!row) return null;
  return {
    email: row.email,
    role: row.role,
    name: row.name,
    isFounder: !!row.is_founder,
    photoDataUrl: row.photo_data_url || null,
    teamsLink: row.teams_link || null,
    linkedinUrl: row.linkedin_url || null,
    childName: row.child_name || null,
    cohort: row.cohort || null,
    board: row.board || null
  };
}

async function requireAuth(c, next) {
  const authHeader = c.req.header("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  const payload = await verifySessionToken(c.env.SESSION_SECRET, token);
  if (!payload) return c.json({ error: "Not signed in." }, 401);
  c.set("auth", payload);
  await next();
}

async function requireFounder(c, next) {
  const auth = c.get("auth");
  if (!auth || !auth.isFounder) return c.json({ error: "Founder access required." }, 403);
  await next();
}

// A tutor or parent may only ever read/write records naming their own
// email as tutorEmail/parentEmail. Founders (always tutors) can see
// everything so they can run the whole schedule, not just their own.
function scopeFilter(auth) {
  if (auth.isFounder) return null;
  if (auth.role === "tutor") return { column: "tutor_email", value: auth.email };
  return { column: "parent_email", value: auth.email };
}

const LOCKOUT_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

// ---------- auth ----------

app.post("/api/login", async (c) => {
  const body = await c.req.json();
  const email = body.email;
  const password = body.password ?? body.pin;
  if (!email || !password) return c.json({ error: "Email and password are required." }, 400);
  const normalizedEmail = String(email).trim().toLowerCase();

  const row = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(normalizedEmail).first();
  if (!row) return c.json({ error: "No account found for that email." }, 404);

  const now = Date.now();
  if (row.locked_until && row.locked_until > now) {
    const minsLeft = Math.ceil((row.locked_until - now) / 60000);
    return c.json({ error: `Too many incorrect attempts. Try again in ${minsLeft} minute${minsLeft === 1 ? "" : "s"}.` }, 423);
  }

  const candidateHash = await hashPin(String(password).trim(), row.pin_salt);
  if (candidateHash !== row.pin_hash) {
    const attempts = (row.failed_attempts || 0) + 1;
    const justLocked = attempts >= LOCKOUT_ATTEMPTS;
    await c.env.DB.prepare(
      "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE email = ?"
    ).bind(justLocked ? 0 : attempts, justLocked ? now + LOCKOUT_MS : null, normalizedEmail).run();
    if (justLocked) {
      return c.json({ error: "Too many incorrect attempts. This account is locked for 15 minutes." }, 423);
    }
    return c.json({ error: "Incorrect password." }, 401);
  }

  if (row.failed_attempts || row.locked_until) {
    await c.env.DB.prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?").bind(normalizedEmail).run();
  }

  const token = await createSessionToken(c.env.SESSION_SECRET, row);
  return c.json({ token, user: userPublic(row) });
});

app.get("/api/me", requireAuth, async (c) => {
  const auth = c.get("auth");
  const row = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(auth.email).first();
  if (!row) return c.json({ error: "Account no longer exists." }, 404);
  return c.json({ user: userPublic(row) });
});

// ---------- users (founder-managed logins) ----------

// Any signed-in account (not just founders) can read the directory: tutors need
// their students' names/cohorts, parents need their tutor's name/Teams link, and
// userPublic() never includes pin_hash/pin_salt, so this leaks nothing sensitive.
app.get("/api/users", requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM users ORDER BY role, name").all();
  return c.json({ users: results.map(userPublic) });
});

app.post("/api/users", requireAuth, requireFounder, async (c) => {
  const body = await c.req.json();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password ?? body.pin ?? "").trim();
  if (!email || password.length < 8) return c.json({ error: "A valid email and a password of at least 8 characters are required." }, 400);

  const existing = await c.env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
  if (existing) return c.json({ error: "An account already exists for that email." }, 409);

  const salt = randomSalt();
  const pinHash = await hashPin(password, salt);

  await c.env.DB.prepare(
    `INSERT INTO users (email, role, name, pin_hash, pin_salt, is_founder, photo_data_url, teams_link, linkedin_url, child_name, cohort, board)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    email,
    body.role === "tutor" ? "tutor" : "parent",
    body.name || "",
    pinHash,
    salt,
    body.isFounder ? 1 : 0,
    body.photoDataUrl || null,
    body.teamsLink || null,
    body.linkedinUrl || null,
    body.childName || null,
    body.cohort || null,
    body.board || null
  ).run();

  return c.json({ ok: true });
});

app.post("/api/users/:email/password", requireAuth, async (c) => {
  const auth = c.get("auth");
  const targetEmail = c.req.param("email").toLowerCase();
  if (!auth.isFounder && auth.email !== targetEmail) return c.json({ error: "You can only change your own password." }, 403);

  const body = await c.req.json();
  const password = String(body.password ?? body.pin ?? "").trim();
  if (password.length < 8) return c.json({ error: "Enter a password of at least 8 characters." }, 400);

  const existing = await c.env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(targetEmail).first();
  if (!existing) return c.json({ error: "That login couldn't be found anymore." }, 404);

  const salt = randomSalt();
  const pinHash = await hashPin(password, salt);
  await c.env.DB.prepare(
    "UPDATE users SET pin_hash = ?, pin_salt = ?, failed_attempts = 0, locked_until = NULL WHERE email = ?"
  ).bind(pinHash, salt, targetEmail).run();

  return c.json({ ok: true });
});

app.patch("/api/users/:email", requireAuth, async (c) => {
  const auth = c.get("auth");
  const targetEmail = c.req.param("email").toLowerCase();
  if (!auth.isFounder && auth.email !== targetEmail) return c.json({ error: "You can only edit your own profile." }, 403);

  const existing = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(targetEmail).first();
  if (!existing) return c.json({ error: "That login couldn't be found anymore." }, 404);

  const body = await c.req.json();
  const fields = {
    name: "name",
    teamsLink: "teams_link",
    linkedinUrl: "linkedin_url",
    photoDataUrl: "photo_data_url",
    childName: "child_name",
    cohort: "cohort",
    board: "board"
  };
  const sets = [];
  const values = [];
  for (const [key, column] of Object.entries(fields)) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      sets.push(`${column} = ?`);
      values.push(body[key] === "" ? null : body[key]);
    }
  }
  if (sets.length === 0) return c.json({ ok: true });

  await c.env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE email = ?`).bind(...values, targetEmail).run();
  const row = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(targetEmail).first();
  return c.json({ ok: true, user: userPublic(row) });
});

app.delete("/api/users/:email", requireAuth, requireFounder, async (c) => {
  const auth = c.get("auth");
  const email = c.req.param("email").toLowerCase();
  const row = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (!row) return c.json({ error: "That login couldn't be found anymore." }, 404);

  await c.env.DB.prepare(
    `INSERT INTO archive (email, role, name, pin_hash, pin_salt, is_founder, photo_data_url, teams_link, linkedin_url, child_name, cohort, board, archived_at, archived_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    row.email, row.role, row.name, row.pin_hash, row.pin_salt, row.is_founder,
    row.photo_data_url, row.teams_link, row.linkedin_url, row.child_name, row.cohort, row.board,
    new Date().toISOString(), auth.email
  ).run();
  await c.env.DB.prepare("DELETE FROM users WHERE email = ?").bind(email).run();

  return c.json({ ok: true });
});

app.get("/api/archive", requireAuth, requireFounder, async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM archive ORDER BY archived_at DESC").all();
  return c.json({ archive: results });
});

app.post("/api/archive/:email/restore", requireAuth, requireFounder, async (c) => {
  const email = c.req.param("email").toLowerCase();
  const row = await c.env.DB.prepare("SELECT * FROM archive WHERE email = ?").bind(email).first();
  if (!row) return c.json({ error: "That archived login couldn't be found." }, 404);

  const existing = await c.env.DB.prepare("SELECT email FROM users WHERE email = ?").bind(email).first();
  if (existing) return c.json({ error: `A login already exists for "${email}". Remove or rename it before restoring this one.` }, 409);

  await c.env.DB.prepare(
    `INSERT INTO users (email, role, name, pin_hash, pin_salt, is_founder, photo_data_url, teams_link, linkedin_url, child_name, cohort, board)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    row.email, row.role, row.name, row.pin_hash, row.pin_salt, row.is_founder,
    row.photo_data_url, row.teams_link, row.linkedin_url, row.child_name, row.cohort, row.board
  ).run();
  await c.env.DB.prepare("DELETE FROM archive WHERE email = ?").bind(email).run();

  return c.json({ ok: true });
});

// ---------- availability ----------

app.get("/api/availability", requireAuth, async (c) => {
  const auth = c.get("auth");
  const scope = scopeFilter(auth);
  const sql = scope && scope.column === "tutor_email"
    ? "SELECT * FROM availability WHERE tutor_email = ? ORDER BY date, start"
    : "SELECT * FROM availability ORDER BY date, start";
  const stmt = scope && scope.column === "tutor_email" ? c.env.DB.prepare(sql).bind(scope.value) : c.env.DB.prepare(sql);
  const { results } = await stmt.all();
  return c.json({ availability: results });
});

app.post("/api/availability", requireAuth, async (c) => {
  const auth = c.get("auth");
  if (auth.role !== "tutor") return c.json({ error: "Only tutors have availability." }, 403);
  const body = await c.req.json();
  const id = newId();
  await c.env.DB.prepare(
    "INSERT INTO availability (id, tutor_email, date, start, end, student_email) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(id, auth.email, body.date, body.start, body.end, body.studentEmail || null).run();
  return c.json({ ok: true, id });
});

app.delete("/api/availability/:id", requireAuth, async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT tutor_email FROM availability WHERE id = ?").bind(id).first();
  if (!row) return c.json({ ok: true });
  if (row.tutor_email !== auth.email && !auth.isFounder) return c.json({ error: "Not your availability." }, 403);
  await c.env.DB.prepare("DELETE FROM availability WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

// ---------- requests ----------

app.get("/api/requests", requireAuth, async (c) => {
  const auth = c.get("auth");
  if (auth.isFounder) {
    const { results } = await c.env.DB.prepare("SELECT * FROM requests ORDER BY created_at DESC").all();
    return c.json({ requests: results });
  }
  const column = auth.role === "tutor" ? "tutor_email" : "parent_email";
  const { results } = await c.env.DB.prepare(`SELECT * FROM requests WHERE ${column} = ? ORDER BY created_at DESC`).bind(auth.email).all();
  return c.json({ requests: results });
});

app.post("/api/requests", requireAuth, async (c) => {
  const auth = c.get("auth");
  const body = await c.req.json();
  if (auth.role === "tutor" && body.tutorEmail !== auth.email) return c.json({ error: "Not your request to make." }, 403);
  if (auth.role === "parent" && body.parentEmail !== auth.email) return c.json({ error: "Not your request to make." }, 403);

  const id = newId();
  await c.env.DB.prepare(
    `INSERT INTO requests (id, direction, tutor_email, parent_email, child_name, cohort, kind, first_date, start, end, status, created_at, renewal_of)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
  ).bind(
    id, body.direction, body.tutorEmail, body.parentEmail, body.childName || null, body.cohort || null,
    body.kind, body.firstDate || null, body.start || null, body.end || null,
    new Date().toISOString(), body.renewalOf || null
  ).run();
  return c.json({ ok: true, id });
});

app.patch("/api/requests/:id", requireAuth, async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT * FROM requests WHERE id = ?").bind(id).first();
  if (!row) return c.json({ error: "That request no longer exists." }, 404);
  if (!auth.isFounder && row.tutor_email !== auth.email && row.parent_email !== auth.email) {
    return c.json({ error: "Not your request." }, 403);
  }
  const body = await c.req.json();
  const status = body.status || row.status;
  const respondedAt = body.status && body.status !== row.status ? new Date().toISOString() : row.responded_at;
  await c.env.DB.prepare("UPDATE requests SET status = ?, responded_at = ? WHERE id = ?").bind(status, respondedAt, id).run();
  return c.json({ ok: true });
});

app.delete("/api/requests/:id", requireAuth, async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT * FROM requests WHERE id = ?").bind(id).first();
  if (!row) return c.json({ ok: true });
  if (!auth.isFounder && row.tutor_email !== auth.email && row.parent_email !== auth.email) {
    return c.json({ error: "Not your request." }, 403);
  }
  await c.env.DB.prepare("DELETE FROM requests WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

// ---------- bookings ----------

app.get("/api/bookings", requireAuth, async (c) => {
  const auth = c.get("auth");
  if (auth.isFounder) {
    const { results } = await c.env.DB.prepare("SELECT * FROM bookings ORDER BY date, start").all();
    return c.json({ bookings: results });
  }
  const column = auth.role === "tutor" ? "tutor_email" : "parent_email";
  const { results } = await c.env.DB.prepare(`SELECT * FROM bookings WHERE ${column} = ? ORDER BY date, start`).bind(auth.email).all();
  return c.json({ bookings: results });
});

app.post("/api/bookings", requireAuth, async (c) => {
  const auth = c.get("auth");
  const body = await c.req.json();
  if (!auth.isFounder && auth.role === "tutor" && body.tutorEmail !== auth.email) return c.json({ error: "Not your booking." }, 403);

  const id = newId();
  await c.env.DB.prepare(
    `INSERT INTO bookings (id, request_id, tutor_email, parent_email, child_name, cohort, date, start, end, completed, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
  ).bind(
    id, body.requestId || null, body.tutorEmail, body.parentEmail, body.childName || null, body.cohort || null,
    body.date, body.start, body.end, new Date().toISOString()
  ).run();
  return c.json({ ok: true, id });
});

app.patch("/api/bookings/:id", requireAuth, async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT * FROM bookings WHERE id = ?").bind(id).first();
  if (!row) return c.json({ error: "That booking no longer exists." }, 404);
  if (!auth.isFounder && row.tutor_email !== auth.email && row.parent_email !== auth.email) {
    return c.json({ error: "Not your booking." }, 403);
  }
  const body = await c.req.json();
  const completed = typeof body.completed === "boolean" ? (body.completed ? 1 : 0) : row.completed;

  // "Notes for Tutor" is written by the family (parent/student login) and read by the
  // tutor on their own calendar; "Notes for Student" is the reverse. Each side can only
  // ever write its own note — a family can't plant a "note for student" and vice versa.
  let noteForTutor = row.note_for_tutor;
  if (typeof body.noteForTutor === "string") {
    if (!auth.isFounder && !(auth.role === "parent" && row.parent_email === auth.email)) {
      return c.json({ error: "Only the family on this booking can leave a note for the tutor." }, 403);
    }
    noteForTutor = body.noteForTutor.trim() || null;
  }
  let noteForStudent = row.note_for_student;
  if (typeof body.noteForStudent === "string") {
    if (!auth.isFounder && !(auth.role === "tutor" && row.tutor_email === auth.email)) {
      return c.json({ error: "Only the tutor on this booking can leave a note for the student." }, 403);
    }
    noteForStudent = body.noteForStudent.trim() || null;
  }

  await c.env.DB.prepare(
    "UPDATE bookings SET completed = ?, note_for_tutor = ?, note_for_student = ? WHERE id = ?"
  ).bind(completed, noteForTutor, noteForStudent, id).run();
  return c.json({ ok: true });
});

app.delete("/api/bookings/:id", requireAuth, async (c) => {
  const auth = c.get("auth");
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT * FROM bookings WHERE id = ?").bind(id).first();
  if (!row) return c.json({ ok: true });
  if (!auth.isFounder && row.tutor_email !== auth.email && row.parent_email !== auth.email) {
    return c.json({ error: "Not your booking." }, 403);
  }
  await c.env.DB.prepare("DELETE FROM bookings WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

// ---------- resources (worksheet library) ----------

app.get("/api/resources", requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM resources ORDER BY category, subject, year_group, title").all();
  return c.json({ resources: results });
});

app.post("/api/resources", requireAuth, requireFounder, async (c) => {
  const auth = c.get("auth");
  const form = await c.req.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return c.json({ error: "No file attached." }, 400);

  const id = newId();
  const safeName = (form.get("title") || file.name || "worksheet").toString().replace(/[^\w\- ]+/g, "").trim() || "worksheet";
  const key = `${id}-${safeName}.pdf`;
  await c.env.RESOURCES.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: "application/pdf" } });

  await c.env.DB.prepare(
    `INSERT INTO resources (id, category, subject, board, year_group, title, file_path, uploaded_by, uploaded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id, form.get("category"), form.get("subject") || null, form.get("board") || null, form.get("yearGroup") || null,
    form.get("title") || safeName, `/api/resources/file/${id}`, auth.email, new Date().toISOString()
  ).run();

  // Remember the R2 key so the file route can find it without guessing.
  await c.env.DB.prepare("UPDATE resources SET r2_key = ? WHERE id = ?").bind(key, id).run().catch(() => {});

  return c.json({ ok: true, id });
});

app.get("/api/resources/file/:id", requireAuth, async (c) => {
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT * FROM resources WHERE id = ?").bind(id).first();
  if (!row) return c.json({ error: "Not found." }, 404);

  // Migrated worksheets are served as static assets at their file_path directly
  // (the [assets] binding handles those before the Worker even runs). This
  // route only serves files that were uploaded after launch, stored in R2.
  const key = row.r2_key;
  if (!key) return c.json({ error: "This file isn't stored here." }, 404);
  const obj = await c.env.RESOURCES.get(key);
  if (!obj) return c.json({ error: "File missing from storage." }, 404);

  return new Response(obj.body, {
    headers: {
      "Content-Type": obj.httpMetadata?.contentType || "application/pdf",
      "Content-Disposition": `attachment; filename="${(row.title || "worksheet").replace(/[^\w\- ]+/g, " ").trim()}.pdf"`
    }
  });
});

app.delete("/api/resources/:id", requireAuth, requireFounder, async (c) => {
  const id = c.req.param("id");
  const row = await c.env.DB.prepare("SELECT * FROM resources WHERE id = ?").bind(id).first();
  if (!row) return c.json({ ok: true });
  if (row.r2_key) await c.env.RESOURCES.delete(row.r2_key).catch(() => {});
  await c.env.DB.prepare("DELETE FROM resources WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

// ---------- reviews ----------
// Students/parents leave a review from the bottom of their own portal. Reviews are
// visible only to founders (Timothy and David) — not to other tutors, and not to
// other families — who see every review in a comment-style feed at the bottom of
// their own portal.

app.get("/api/reviews", requireAuth, requireFounder, async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM reviews ORDER BY created_at DESC").all();
  return c.json({ reviews: results });
});

// A parent/student can see their own past reviews (to confirm what they sent),
// but never anyone else's — that stays founder-only above.
app.get("/api/reviews/mine", requireAuth, async (c) => {
  const auth = c.get("auth");
  if (auth.role !== "parent") return c.json({ reviews: [] });
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM reviews WHERE parent_email = ? ORDER BY created_at DESC"
  ).bind(auth.email).all();
  return c.json({ reviews: results });
});

app.post("/api/reviews", requireAuth, async (c) => {
  const auth = c.get("auth");
  if (auth.role !== "parent") return c.json({ error: "Only students and parents can leave a review." }, 403);

  const body = await c.req.json();
  const comment = String(body.comment || "").trim();
  if (!comment) return c.json({ error: "Write a few words before sending." }, 400);
  const ratingNum = Number(body.rating);
  const rating = Number.isInteger(ratingNum) && ratingNum >= 1 && ratingNum <= 5 ? ratingNum : null;

  const id = newId();
  await c.env.DB.prepare(
    "INSERT INTO reviews (id, parent_email, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(id, auth.email, rating, comment, new Date().toISOString()).run();

  return c.json({ ok: true, id });
});

app.delete("/api/reviews/:id", requireAuth, requireFounder, async (c) => {
  const id = c.req.param("id");
  await c.env.DB.prepare("DELETE FROM reviews WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

app.notFound((c) => c.json({ error: "Not found." }, 404));

export default app;
