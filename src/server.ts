import dotenv from "dotenv";
dotenv.config();

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import prisma from "./prisma";
import {
  apiLimiter,
  loginLimiter,
  quizLimiter,
  adminLimiter,
  validateUsername,
  validatePin,
  validateAdminPin,
  validateQuizId,
  validateSelectedOption,
  sanitize,
  bodySizeGuard,
  extraSecurityHeaders,
  isAccountLocked,
  recordFailedLogin,
  clearFailedLogins,
  logSecurity,
  getSecurityLog,
} from "./security";

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PIN = process.env.ADMIN_PIN;
const isProduction = process.env.NODE_ENV === "production";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

if (!JWT_SECRET || !ADMIN_PIN) {
  console.error("FATAL: Missing required env vars: JWT_SECRET, ADMIN_PIN");
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE STACK
// ═══════════════════════════════════════════════════════════════

// 1. Helmet — ~15 security headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  // HSTS: forces HTTPS in production for 1 year
  hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
}));

// 2. Extra custom headers
app.use(extraSecurityHeaders);

// 3. CORS — locked to known origins only
app.use(cors({
  origin: [
    FRONTEND_URL,
    "http://localhost:3000",
    "https://localhost:3000",
    "http://127.0.0.1:3000",
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400,
}));

// 4. Body parsing with 10KB limit
app.use(express.json({ limit: "10kb" }));

// 5. Global rate limiter
app.use("/api", apiLimiter);

// 6. Security event logging middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  // Log suspicious patterns
  const suspicious = [
    "../", "..\\", "<script", "javascript:", "eval(", "exec(",
    "union select", "drop table", "1=1", "' or '",
  ];
  const url = req.url.toLowerCase();
  const body = JSON.stringify(req.body || {}).toLowerCase();
  for (const pattern of suspicious) {
    if (url.includes(pattern) || body.includes(pattern)) {
      logSecurity("SUSPICIOUS_REQUEST", pattern, `${req.method} ${req.url}`, req);
      break;
    }
  }
  next();
});

// ═══════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  const token = authHeader.substring(7);

  if (token.length > 2048) {
    logSecurity("INVALID_TOKEN", "Token too long", "", req);
    return res.status(401).json({ error: "Invalid token" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: number };
    req.body = req.body || {};
    req.body.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ═══════════════════════════════════════════════════════════════
// AUTH: LOGIN (with account lockout)
// ═══════════════════════════════════════════════════════════════

app.post("/api/auth/login", loginLimiter, async (req: Request, res: Response) => {
  try {
    const { username, pin } = req.body;

    // Input validation
    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const pinErr = validatePin(pin);
    if (pinErr) return res.status(400).json({ error: pinErr });

    const cleanUsername = sanitize(username).toLowerCase();

    // Check account lockout
    if (isAccountLocked(cleanUsername)) {
      logSecurity("LOGIN_BLOCKED", cleanUsername, "Account locked", req);
      return res.status(423).json({ error: "Account locked due to too many failed attempts. Try again in 15 minutes." });
    }

    const user = await prisma.user.findUnique({
      where: { username: cleanUsername },
    });

    // Constant-time comparison (prevents timing attacks)
    if (!user || !timingSafeEqual(user.pin, pin)) {
      recordFailedLogin(cleanUsername);
      logSecurity("LOGIN_FAILED", cleanUsername, "", req);
      // Generic error — doesn't reveal whether username exists (prevents user enumeration)
      return res.status(401).json({ error: "Invalid username or PIN" });
    }

    // Success — clear failed attempts
    clearFailedLogins(cleanUsername);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "24h" });

    logSecurity("LOGIN_SUCCESS", cleanUsername, "", req);
    res.json({ token, userId: user.id, username: user.username });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// QUIZ ROUTES
// ═══════════════════════════════════════════════════════════════

app.get("/api/quizzes", authMiddleware, async (req: Request, res: Response) => {
  try {
    const userId = req.body.userId!;
    const quizzes = await prisma.quiz.findMany({
      include: {
        questions: { select: { id: true } },
        attempts: { where: { userId }, select: { id: true } },
      },
    });
    res.json(quizzes.map((q) => ({
      id: q.id,
      title: q.title,
      timeLimit: q.timeLimit,
      questionCount: q.questions.length,
      canStart: q.attempts.length === 0,
    })));
  } catch (error) {
    console.error("Get quizzes error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/quiz/:quizId/questions", authMiddleware, quizLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    // Must have active attempt to see questions
    const userId = req.body.userId!;
    const attempt = await prisma.attempt.findFirst({
      where: { userId, quizId: Number(quizId), status: "in-progress" },
    });
    if (!attempt) {
      return res.status(403).json({ error: "You must start the quiz before viewing questions" });
    }

    const questions = await prisma.question.findMany({
      where: { quizId: Number(quizId) },
      select: { id: true, text: true, options: true, correctAnswer: true },
      orderBy: { id: "asc" },
    });
    res.json(questions);
  } catch (error) {
    console.error("Get questions error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/quiz/:quizId", authMiddleware, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const quiz = await prisma.quiz.findUnique({
      where: { id: Number(quizId) },
      select: { id: true, title: true, timeLimit: true },
    });
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });
    res.json(quiz);
  } catch (error) {
    console.error("Get quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/quiz/:quizId/start", authMiddleware, quizLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const userId = req.body.userId!;
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const quiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) } });
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    const existing = await prisma.attempt.findFirst({ where: { userId, quizId: Number(quizId) } });
    if (existing) return res.status(400).json({ error: "Attempt already exists" });

    const attempt = await prisma.attempt.create({
      data: { userId, quizId: Number(quizId), score: 0, status: "in-progress" },
    });
    logSecurity("QUIZ_STARTED", `User ${userId} started quiz ${quizId}`, "", req);
    res.json({ attemptId: attempt.id });
  } catch (error) {
    console.error("Start quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/quiz/:quizId/answer", authMiddleware, quizLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const userId = req.body.userId!;
    const { questionId, selectedOption } = req.body;

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    if (questionId === undefined) return res.status(400).json({ error: "questionId is required" });

    const optErr = validateSelectedOption(selectedOption);
    if (optErr) return res.status(400).json({ error: optErr });

    const question = await prisma.question.findUnique({
      where: { id: Number(questionId) },
      select: { quizId: true },
    });
    if (!question || question.quizId !== Number(quizId)) {
      return res.status(404).json({ error: "Question not found in this quiz" });
    }

    const attempt = await prisma.attempt.findFirst({
      where: { userId, quizId: Number(quizId), status: "in-progress" },
    });
    if (!attempt) return res.status(404).json({ error: "No active quiz attempt found." });

    // Time enforcement
    const quiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) }, select: { timeLimit: true } });
    if (quiz) {
      const elapsed = (Date.now() - attempt.createdAt.getTime()) / 1000;
      if (elapsed > quiz.timeLimit + 30) {
        logSecurity("ANSWER_AFTER_EXPIRY", `User ${userId} quiz ${quizId}`, "", req);
        return res.status(403).json({ error: "Quiz time has expired" });
      }
    }

    const existing = await prisma.answer.findFirst({
      where: { attemptId: attempt.id, questionId: Number(questionId) },
    });

    if (existing) {
      await prisma.answer.update({ where: { id: existing.id }, data: { selectedOption: Number(selectedOption) } });
    } else {
      await prisma.answer.create({
        data: { attemptId: attempt.id, questionId: Number(questionId), selectedOption: Number(selectedOption) },
      });
    }
    res.json({ success: true });
  } catch (error) {
    console.error("Submit answer error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/quiz/:quizId/tab-switch", authMiddleware, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const userId = req.body.userId!;
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const attempt = await prisma.attempt.findFirst({
      where: { userId, quizId: Number(quizId), status: "in-progress" },
    });
    if (!attempt) return res.status(404).json({ error: "No active attempt" });

    const updated = await prisma.attempt.update({
      where: { id: attempt.id },
      data: { tabSwitches: attempt.tabSwitches + 1 },
      select: { tabSwitches: true },
    });

    const shouldAutoSubmit = updated.tabSwitches >= 2;
    if (shouldAutoSubmit) {
      logSecurity("TAB_SWITCH_AUTO_SUBMIT", `User ${userId} quiz ${quizId}`, "", req);
    }

    res.json({ tabSwitches: updated.tabSwitches, shouldAutoSubmit });
  } catch (error) {
    console.error("Tab switch error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/quiz/:quizId/finish", authMiddleware, quizLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const userId = req.body.userId!;
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const attempt = await prisma.attempt.findFirst({
      where: { userId, quizId: Number(quizId), status: "in-progress" },
      include: { answers: { include: { question: true } } },
    });
    if (!attempt) return res.status(404).json({ error: "No active quiz attempt found" });
    if (attempt.status === "completed") return res.status(400).json({ error: "Quiz already finalized" });

    const questions = await prisma.question.findMany({ where: { quizId: Number(quizId) } });

    let correctCount = 0;
    for (const ans of attempt.answers) {
      const question = questions.find((q) => q.id === ans.questionId);
      if (question && ans.selectedOption === question.correctAnswer) correctCount++;
    }

    const score = questions.length > 0 ? (correctCount / questions.length) * 100 : 0;
    const status = score >= 75 ? "passed" : "not-passed";

    await prisma.attempt.update({ where: { id: attempt.id }, data: { score, status } });

    logSecurity("QUIZ_FINISHED", `User ${userId} quiz ${quizId} score=${score.toFixed(1)}% ${status}`, "", req);
    res.json({ score, correctCount, totalQuestions: questions.length, status });
  } catch (error) {
    console.error("Finalize quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════

app.post("/api/admin/reset-attempt", adminLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { username, quizId, adminPin } = req.body;

    const pinErr = validateAdminPin(adminPin);
    if (pinErr) return res.status(400).json({ error: pinErr });
    if (adminPin !== ADMIN_PIN) {
      logSecurity("ADMIN_AUTH_FAILED", "", "", req);
      return res.status(403).json({ error: "Invalid admin PIN" });
    }

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const cleanUsername = sanitize(username).toLowerCase();
    const user = await prisma.user.findUnique({ where: { username: cleanUsername } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const attempt = await prisma.attempt.findFirst({
      where: { userId: user.id, quizId: Number(quizId) },
      include: { answers: true },
    });
    if (!attempt) return res.status(404).json({ error: "No attempt found" });

    await prisma.answer.deleteMany({ where: { attemptId: attempt.id } });
    await prisma.attempt.delete({ where: { id: attempt.id } });

    logSecurity("ADMIN_RESET", `Reset ${cleanUsername} quiz ${quizId}`, "", req);
    res.json({ success: true, message: `Attempt for "${cleanUsername}" on quiz ${quizId} cleared.` });
  } catch (error) {
    console.error("Reset attempt error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/admin/attempts", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) {
      logSecurity("ADMIN_AUTH_FAILED", "", "", req);
      return res.status(403).json({ error: "Invalid admin PIN" });
    }

    const attempts = await prisma.attempt.findMany({
      include: {
        user: { select: { id: true, username: true } },
        quiz: { select: { id: true, title: true } },
      },
      orderBy: { createdAt: "desc" },
    });
    res.json(attempts.map((a) => ({
      attemptId: a.id,
      userId: a.user.id,
      username: a.user.username,
      quizId: a.quiz.id,
      quizTitle: a.quiz.title,
      score: a.score,
      status: a.status,
      tabSwitches: a.tabSwitches,
      createdAt: a.createdAt,
    })));
  } catch (error) {
    console.error("List attempts error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Security log viewer (admin only)
app.get("/api/admin/security-log", adminLimiter, (req: Request, res: Response) => {
  const { adminPin } = req.query;
  if (adminPin !== ADMIN_PIN) {
    return res.status(403).json({ error: "Invalid admin PIN" });
  }
  res.json(getSecurityLog().slice(0, 100));
});

// ═══════════════════════════════════════════════════════════════
// ADMIN: QUIZ MANAGEMENT
// ═══════════════════════════════════════════════════════════════

// List all quizzes with question counts
app.get("/api/admin/quizzes", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const quizzes = await prisma.quiz.findMany({
      include: { questions: { select: { id: true } } },
      orderBy: { id: "asc" },
    });

    res.json(quizzes.map((q) => ({
      id: q.id,
      title: q.title,
      timeLimit: q.timeLimit,
      questionCount: q.questions.length,
    })));
  } catch (error) {
    console.error("Admin list quizzes error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a new quiz
app.post("/api/admin/quizzes", adminLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { adminPin, title, timeLimit } = req.body;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    if (!title || typeof title !== "string" || title.trim().length < 2) {
      return res.status(400).json({ error: "Quiz title must be at least 2 characters" });
    }
    if (!timeLimit || typeof timeLimit !== "number" || timeLimit < 30) {
      return res.status(400).json({ error: "Time limit must be at least 30 seconds" });
    }

    const quiz = await prisma.quiz.create({
      data: { title: sanitize(title).trim(), timeLimit },
    });

    logSecurity("ADMIN_QUIZ_CREATED", `Quiz ${quiz.id}: ${quiz.title}`, "", req);
    res.json({ id: quiz.id, title: quiz.title, timeLimit: quiz.timeLimit });
  } catch (error) {
    console.error("Admin create quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete a quiz and all its questions/answers
app.delete("/api/admin/quizzes/:quizId", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const quiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) }, include: { questions: true } });
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    // Delete answers → attempts → questions → quiz
    const questionIds = quiz.questions.map((q) => q.id);
    await prisma.answer.deleteMany({ where: { questionId: { in: questionIds } } });
    await prisma.attempt.deleteMany({ where: { quizId: Number(quizId) } });
    await prisma.question.deleteMany({ where: { quizId: Number(quizId) } });
    await prisma.quiz.delete({ where: { id: Number(quizId) } });

    logSecurity("ADMIN_QUIZ_DELETED", `Quiz ${quizId}: ${quiz.title}`, "", req);
    res.json({ success: true, message: `Quiz "${quiz.title}" and all its data deleted` });
  } catch (error) {
    console.error("Admin delete quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// List questions for a quiz
app.get("/api/admin/quizzes/:quizId/questions", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const questions = await prisma.question.findMany({
      where: { quizId: Number(quizId) },
      orderBy: { id: "asc" },
    });

    res.json(questions.map((q) => ({
      id: q.id,
      text: q.text,
      options: q.options,
      correctAnswer: q.correctAnswer,
    })));
  } catch (error) {
    console.error("Admin list questions error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Add a single question
app.post("/api/admin/quizzes/:quizId/questions", adminLimiter, bodySizeGuard(10), async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { adminPin, text, options, correctAnswer } = req.body;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    if (!text || typeof text !== "string" || text.trim().length < 5) {
      return res.status(400).json({ error: "Question text must be at least 5 characters" });
    }
    if (!Array.isArray(options) || options.length !== 4) {
      return res.status(400).json({ error: "Must provide exactly 4 options" });
    }
    if (typeof correctAnswer !== "number" || correctAnswer < 1 || correctAnswer > 4) {
      return res.status(400).json({ error: "correctAnswer must be 1-4" });
    }

    // Verify quiz exists
    const quiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) } });
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    const question = await prisma.question.create({
      data: {
        quizId: Number(quizId),
        text: sanitize(text).trim(),
        options: options.map((o: any) => String(o).trim()),
        correctAnswer,
      },
    });

    res.json({ id: question.id, text: question.text, options: question.options, correctAnswer: question.correctAnswer });
  } catch (error) {
    console.error("Admin add question error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Bulk add questions
app.post("/api/admin/quizzes/:quizId/questions/bulk", adminLimiter, bodySizeGuard(100), async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { adminPin, questions } = req.body;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    if (!Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({ error: "Provide an array of questions" });
    }
    if (questions.length > 200) {
      return res.status(400).json({ error: "Maximum 200 questions per bulk insert" });
    }

    const quiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) } });
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    // Validate all questions
    const errors: string[] = [];
    const validQuestions: Array<{ quizId: number; text: string; options: string[]; correctAnswer: number }> = [];

    for (let i = 0; i < questions.length; i++) {
      const q = questions[i];
      if (!q.text || typeof q.text !== "string" || q.text.trim().length < 5) {
        errors.push(`Question ${i + 1}: text must be at least 5 characters`);
        continue;
      }
      if (!Array.isArray(q.options) || q.options.length !== 4) {
        errors.push(`Question ${i + 1}: must have exactly 4 options`);
        continue;
      }
      if (typeof q.correctAnswer !== "number" || q.correctAnswer < 1 || q.correctAnswer > 4) {
        errors.push(`Question ${i + 1}: correctAnswer must be 1-4`);
        continue;
      }
      validQuestions.push({
        quizId: Number(quizId),
        text: sanitize(q.text).trim(),
        options: q.options.map((o: any) => String(o).trim()),
        correctAnswer: q.correctAnswer,
      });
    }

    if (errors.length > 0) {
      return res.status(400).json({ error: "Validation failed", details: errors });
    }

    // Insert all at once
    const result = await prisma.question.createMany({ data: validQuestions });

    logSecurity("ADMIN_BULK_INSERT", `${result.count} questions into quiz ${quizId}`, "", req);
    res.json({ success: true, count: result.count });
  } catch (error) {
    console.error("Admin bulk insert error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update a question
app.put("/api/admin/questions/:questionId", adminLimiter, bodySizeGuard(10), async (req: Request, res: Response) => {
  try {
    const { questionId } = req.params;
    const { adminPin, text, options, correctAnswer } = req.body || {};
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const question = await prisma.question.findUnique({ where: { id: Number(questionId) } });
    if (!question) return res.status(404).json({ error: "Question not found" });

    const updates: any = {};
    if (text !== undefined) {
      const clean = sanitize(text);
      if (!clean || clean.length < 2) return res.status(400).json({ error: "Question text is required" });
      updates.text = clean;
    }
    if (options !== undefined) {
      if (!Array.isArray(options) || options.length !== 4) {
        return res.status(400).json({ error: "Exactly 4 options are required" });
      }
      const cleanOptions = options.map((o: any) => sanitize(o));
      if (cleanOptions.some((o: string) => !o || o.length > 200)) {
        return res.status(400).json({ error: "Each option must be 1-200 characters" });
      }
      updates.options = cleanOptions;
    }
    if (correctAnswer !== undefined) {
      const num = Number(correctAnswer);
      if (!Number.isInteger(num) || num < 1 || num > 4) {
        return res.status(400).json({ error: "Correct answer must be 1-4" });
      }
      updates.correctAnswer = num;
    }

    const updated = await prisma.question.update({
      where: { id: Number(questionId) },
      data: updates,
    });

    logSecurity("ADMIN_QUESTION_UPDATED", `Question ${questionId}`, "", req);
    res.json({
      id: updated.id,
      text: updated.text,
      options: updated.options,
      correctAnswer: updated.correctAnswer,
    });
  } catch (error) {
    console.error("Admin update question error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete a question
app.delete("/api/admin/questions/:questionId", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { questionId } = req.params;
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const question = await prisma.question.findUnique({ where: { id: Number(questionId) } });
    if (!question) return res.status(404).json({ error: "Question not found" });

    await prisma.answer.deleteMany({ where: { questionId: Number(questionId) } });
    await prisma.question.delete({ where: { id: Number(questionId) } });

    logSecurity("ADMIN_QUESTION_DELETED", `Question ${questionId}`, "", req);
    res.json({ success: true });
  } catch (error) {
    console.error("Admin delete question error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN: USER MANAGEMENT
// ═══════════════════════════════════════════════════════════════

// List all users with attempt counts
app.get("/api/admin/users", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        attempts: {
          select: {
            id: true,
            quizId: true,
            score: true,
            status: true,
            tabSwitches: true,
            createdAt: true,
            quiz: { select: { title: true } },
          },
        },
      },
      orderBy: { id: "asc" },
    });

    res.json(users.map((u) => ({
      id: u.id,
      username: u.username,
      attemptCount: u.attempts.length,
      attempts: u.attempts.map((a) => ({
        attemptId: a.id,
        quizId: a.quizId,
        quizTitle: a.quiz.title,
        score: a.score,
        status: a.status,
        tabSwitches: a.tabSwitches,
        createdAt: a.createdAt,
      })),
    })));
  } catch (error) {
    console.error("Admin list users error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a new user
app.post("/api/admin/users", adminLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { adminPin, username, pin } = req.body || {};
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const pinErr = validatePin(pin);
    if (pinErr) return res.status(400).json({ error: pinErr });

    const cleanUsername = sanitize(username).toLowerCase();

    // Check if user already exists
    const existing = await prisma.user.findUnique({ where: { username: cleanUsername } });
    if (existing) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const user = await prisma.user.create({
      data: { username: cleanUsername, pin: pin.trim() },
      select: { id: true, username: true },
    });

    logSecurity("ADMIN_USER_CREATED", `User ${user.id}: ${user.username}`, "", req);
    res.json({ id: user.id, username: user.username });
  } catch (error) {
    console.error("Admin create user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete a user and all their attempts
app.delete("/api/admin/users/:userId", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const user = await prisma.user.findUnique({ where: { id: Number(userId) } });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Delete answers → attempts → user
    const attempts = await prisma.attempt.findMany({ where: { userId: Number(userId) }, select: { id: true } });
    const attemptIds = attempts.map((a) => a.id);
    await prisma.answer.deleteMany({ where: { attemptId: { in: attemptIds } } });
    await prisma.attempt.deleteMany({ where: { userId: Number(userId) } });
    await prisma.user.delete({ where: { id: Number(userId) } });

    logSecurity("ADMIN_USER_DELETED", `User ${userId}: ${user.username}`, "", req);
    res.json({ success: true, message: `User "${user.username}" deleted` });
  } catch (error) {
    console.error("Admin delete user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get individual user results
app.get("/api/admin/users/:userId/results", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { adminPin } = req.query;
    if (adminPin !== ADMIN_PIN) return res.status(403).json({ error: "Invalid admin PIN" });

    const user = await prisma.user.findUnique({
      where: { id: Number(userId) },
      select: { id: true, username: true },
    });
    if (!user) return res.status(404).json({ error: "User not found" });

    const attempts = await prisma.attempt.findMany({
      where: { userId: Number(userId) },
      include: {
        quiz: { select: { id: true, title: true, timeLimit: true } },
        answers: {
          include: {
            question: { select: { id: true, text: true, options: true, correctAnswer: true } },
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({
      user,
      attempts: attempts.map((a) => ({
        attemptId: a.id,
        quizId: a.quiz.id,
        quizTitle: a.quiz.title,
        timeLimit: a.quiz.timeLimit,
        score: a.score,
        status: a.status,
        tabSwitches: a.tabSwitches,
        startedAt: a.createdAt,
        answers: a.answers.map((ans) => ({
          questionId: ans.question.id,
          questionText: ans.question.text,
          options: ans.question.options,
          correctAnswer: ans.question.correctAnswer,
          selectedOption: ans.selectedOption,
          isCorrect: ans.selectedOption === ans.question.correctAnswer,
        })),
      })),
    });
  } catch (error) {
    console.error("Admin user results error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// USER DASHBOARD
// ═══════════════════════════════════════════════════════════════

app.get("/api/users/me", authMiddleware, async (req: Request, res: Response) => {
  try {
    const userId = req.body.userId!;
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, username: true } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const attempts = await prisma.attempt.findMany({
      where: { userId },
      include: {
        quiz: { select: { id: true, title: true, timeLimit: true } },
        answers: { include: { question: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({
      user,
      history: attempts.map((a) => ({
        quizId: a.quiz.id,
        quizTitle: a.quiz.title,
        score: a.score,
        percentage: a.score,
        status: a.status === "passed" || a.score >= 75 ? "Passed" : "Not Passed",
        completedAt: a.createdAt,
        answers: a.answers.map((ans) => ({
          questionId: ans.questionId,
          questionText: ans.question.text,
          selectedOption: ans.selectedOption,
          correctAnswer: ans.question.correctAnswer,
          isCorrect: ans.selectedOption === ans.question.correctAnswer,
        })),
      })),
    });
  } catch (error) {
    console.error("Get dashboard error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// HEALTH CHECK & ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ═══════════════════════════════════════════════════════════════
// TIMING-SAFE STRING COMPARISON (prevents timing attacks)
// ═══════════════════════════════════════════════════════════════

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    let result = a.length ^ b.length;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i % b.length);
    }
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// ═══════════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════════

const PORT = Number(process.env.PORT) || 7860;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  logSecurity("SERVER_START", `Port ${PORT}`);
});
