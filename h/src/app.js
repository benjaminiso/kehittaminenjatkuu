// src/app.js
import express from "express";
import session from "express-session";
import resourcesRouter from "./routes/resources.routes.js";
import reservationsRouter from "./routes/reservations.routes.js";
import authRoutes from "./routes/auth.routes.js";
import path from "path";
import { fileURLToPath } from "url";

// --- Fix for __dirname in ESM ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express(); // Must be first before using app

// --- Middleware ---

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || "super-secret-key",
  resave: false,
  saveUninitialized: false
}));

// Parse JSON bodies
app.use(express.json());

// Serve static files
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

// --- Authentication middleware ---
function requireAuth(req, res, next) {
  if (req.session?.user) {
    next();
  } else {
    res.redirect("/login");
  }
}

// --- Routes ---

// Frontend pages
app.get("/", (_req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/resources", (_req, res) => {
  res.sendFile(path.join(__dirname, "views/resources.html"));
});

app.get("/reservations", requireAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, "views/reservations.html"));
});

app.get("/login", (_req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

app.get("/register", (_req, res) => {
  res.sendFile(path.join(publicDir, "register.html"));
});

// --- API routes ---
app.use("/api/resources", resourcesRouter);
app.use("/api/reservations", reservationsRouter);
app.use("/api/auth", authRoutes);

// --- API 404 ---
app.use("/api", (_req, res) => {
  return res.status(404).json({
    ok: false,
    error: "Not found",
    path: _req.originalUrl,
  });
});

// --- Frontend 404 ---
app.use((_req, res) => {
  return res.status(404).send("404 - Page not found");
});

// --- Central error handler ---
app.use((err, _req, res, next) => {
  console.error("Unhandled error:", err);
  if (res.headersSent) return next(err);

  return res.status(500).json({
    ok: false,
    error: "Internal server error",
  });
});

export default app;