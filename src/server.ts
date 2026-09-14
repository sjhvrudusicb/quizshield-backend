import dotenv from "dotenv";
dotenv.config();

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";
import prisma from "./prisma";
import {
  apiLimiter,
  loginLimiter,
  registerLimiter,
  quizLimiter,
  adminLimiter,
  validateUsername,
  validatePin,
  validateEmail,
  validateRetakeReason,
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
import {
  sendWelcomeEmail,
  sendAdminRetakeNotification,
  sendStudentRetakeApproval,
} from "./email";

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

// 2. Gzip compression — reduces response size by ~70%
app.use(compression({
  threshold: 1024,
  level: 6,
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
  allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
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
// HEALTH CHECK (fast, no auth, no rate limit)
// ═══════════════════════════════════════════════════════════════

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: Date.now() });
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
    const decoded = jwt.verify(token, JWT_SECRET!) as { userId: number };
    req.body = req.body || {};
    req.body.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ═══════════════════════════════════════════════════════════════
// AUTH: REGISTRATION (Self-service with @gmail.com & auto-generated 5-digit PIN)
// ═══════════════════════════════════════════════════════════════

app.post("/api/auth/register", registerLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { username, email } = req.body || {};

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const emailErr = validateEmail(email);
    if (emailErr) return res.status(400).json({ error: emailErr });

    const cleanUsername = sanitize(username).toLowerCase();
    const cleanEmail = sanitize(email).toLowerCase();

    // Verify unique username or email
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { username: cleanUsername },
          { email: cleanEmail },
        ],
      },
    });

    if (existingUser) {
      if (existingUser.username === cleanUsername) {
        return res.status(409).json({ error: "This username is already taken. Please choose another." });
      }
      if (existingUser.email === cleanEmail) {
        return res.status(409).json({ error: "An account with this Gmail address already exists." });
      }
    }

    // Generate cryptographically random 5-digit PIN (10000 to 99999)
    const pin = crypto.randomInt(10000, 100000).toString();
    const pinHash = await bcrypt.hash(pin, 10);

    const newUser = await prisma.user.create({
      data: {
        username: cleanUsername,
        email: cleanEmail,
        pinHash,
      },
    });

    logSecurity("USER_REGISTERED", cleanUsername, `Email: ${cleanEmail}`, req);

    // Send welcome email with generated PIN asynchronously
    sendWelcomeEmail(cleanEmail, cleanUsername, pin).catch((err) => {
      console.error("[Register] Error sending welcome email:", err);
    });

    res.status(201).json({
      success: true,
      message: `Registration successful! Your 5-digit PIN has been emailed to ${cleanEmail}. Check your inbox to log in.`,
      username: newUser.username,
      email: newUser.email,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

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

    // Constant-time hash verification via bcrypt (prevents timing attacks)
    const isValid = user ? await bcrypt.compare(pin, user.pinHash) : false;
    if (!user || !isValid) {
      recordFailedLogin(cleanUsername);
      logSecurity("LOGIN_FAILED", cleanUsername, "", req);
      // Generic error — doesn't reveal whether username exists (prevents user enumeration)
      return res.status(401).json({ error: "Invalid username or PIN" });
    }

    // Success — clear failed attempts
    clearFailedLogins(cleanUsername);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "24h" });

    logSecurity("LOGIN_SUCCESS", cleanUsername, "", req);
    res.json({ token, userId: user.id, username: user.username, email: user.email });
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
        attempts: {
          where: { userId },
          select: { id: true, score: true, status: true, tabSwitches: true, createdAt: true },
          orderBy: { createdAt: "desc" },
          take: 1,
        },
        retakeRequests: {
          where: { userId },
          select: { id: true, status: true, category: true, reason: true, createdAt: true, resolvedAt: true },
          orderBy: { createdAt: "desc" },
          take: 1,
        },
      },
      orderBy: { id: "asc" },
    });

    res.json(quizzes.map((q) => {
      const latestAttempt = q.attempts[0] || null;
      const latestRetake = q.retakeRequests[0] || null;
      return {
        id: q.id,
        title: q.title,
        timeLimit: q.timeLimit,
        questionCount: q.questions.length,
        canStart: q.attempts.length === 0,
        attempt: latestAttempt ? {
          id: latestAttempt.id,
          score: latestAttempt.score,
          status: latestAttempt.status,
          tabSwitches: latestAttempt.tabSwitches,
          createdAt: latestAttempt.createdAt,
        } : null,
        retakeRequest: latestRetake ? {
          id: latestRetake.id,
          status: latestRetake.status,
          category: latestRetake.category,
          reason: latestRetake.reason,
          createdAt: latestRetake.createdAt,
        } : null,
      };
    }));
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
      select: { id: true, text: true, options: true },
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
    const { answers: batchAnswers, tabSwitches } = req.body || {};
    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const attempt = await prisma.attempt.findFirst({
      where: { userId, quizId: Number(quizId), status: "in-progress" },
    });
    if (!attempt) return res.status(404).json({ error: "No active quiz attempt found" });
    if (attempt.status === "completed") return res.status(400).json({ error: "Quiz already finalized" });

    const questions = await prisma.question.findMany({ where: { quizId: Number(quizId) } });

    // Batch mode: frontend sends all answers at once
    if (Array.isArray(batchAnswers)) {
      console.log("[FINISH] Batch mode. Received", batchAnswers.length, "answers");
      console.log("[FINISH] Sample answers:", JSON.stringify(batchAnswers.slice(0, 3)));

      // Delete any existing answers (from prior partial saves)
      await prisma.answer.deleteMany({ where: { attemptId: attempt.id } });

      // Batch insert all answers
      const validAnswers = batchAnswers
        .filter((a: any) => a.questionId && a.selectedOption >= 1 && a.selectedOption <= 4)
        .map((a: any) => ({
          attemptId: attempt.id,
          questionId: Number(a.questionId),
          selectedOption: Number(a.selectedOption),
        }));

      console.log("[FINISH] Valid answers after filter:", validAnswers.length);

      if (validAnswers.length > 0) {
        await prisma.answer.createMany({ data: validAnswers });
      }

      // Update tab switches if provided
      if (typeof tabSwitches === "number" && tabSwitches > 0) {
        await prisma.attempt.update({
          where: { id: attempt.id },
          data: { tabSwitches: Math.min(tabSwitches, 100) },
        });
      }

      // Reload answers with questions for scoring
      const savedAnswers = await prisma.answer.findMany({
        where: { attemptId: attempt.id },
        include: { question: true },
      });

      console.log("[FINISH] Saved answers count:", savedAnswers.length);
      if (savedAnswers.length > 0) {
        const sample = savedAnswers[0];
        console.log("[FINISH] Sample saved: selectedOption=", sample.selectedOption, "correctAnswer=", sample.question.correctAnswer, "type selected=", typeof sample.selectedOption, "type correct=", typeof sample.question.correctAnswer);
      }

      let correctCount = 0;
      for (const ans of savedAnswers) {
        if (ans.selectedOption === ans.question.correctAnswer) correctCount++;
      }

      const score = questions.length > 0 ? (correctCount / questions.length) * 100 : 0;
      const status = score >= 75 ? "passed" : "not-passed";

      await prisma.attempt.update({ where: { id: attempt.id }, data: { score, status } });

      logSecurity("QUIZ_FINISHED", `User ${userId} quiz ${quizId} score=${score.toFixed(1)}% ${status} (batch)`, "", req);
      res.json({ score, correctCount, totalQuestions: questions.length, status });
    } else {
      // Legacy mode: answers already saved individually during quiz
      const existingAnswers = await prisma.answer.findMany({
        where: { attemptId: attempt.id },
        include: { question: true },
      });

      let correctCount = 0;
      for (const ans of existingAnswers) {
        if (ans.selectedOption === ans.question.correctAnswer) correctCount++;
      }

      const score = questions.length > 0 ? (correctCount / questions.length) * 100 : 0;
      const status = score >= 75 ? "passed" : "not-passed";

      await prisma.attempt.update({ where: { id: attempt.id }, data: { score, status } });

      logSecurity("QUIZ_FINISHED", `User ${userId} quiz ${quizId} score=${score.toFixed(1)}% ${status}`, "", req);
      res.json({ score, correctCount, totalQuestions: questions.length, status });
    }
  } catch (error) {
    console.error("Finalize quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// RETAKE / 2ND CHANCE REQUEST (Student Route)
// ═══════════════════════════════════════════════════════════════

app.post("/api/quiz/:quizId/request-retake", authMiddleware, quizLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { category, reason } = req.body || {};
    const userId = req.body.userId!;

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const reasonErr = validateRetakeReason(reason);
    if (reasonErr) return res.status(400).json({ error: reasonErr });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const quiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) } });
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    // Ensure student actually attempted this quiz
    const attempt = await prisma.attempt.findFirst({
      where: { userId, quizId: Number(quizId) },
      orderBy: { createdAt: "desc" },
    });

    if (!attempt) {
      return res.status(400).json({ error: "You cannot request a 2nd chance for a quiz topic you have not attempted." });
    }

    // Check if there is already a pending request
    const existingPending = await prisma.retakeRequest.findFirst({
      where: { userId, quizId: Number(quizId), status: "pending" },
    });

    if (existingPending) {
      return res.status(409).json({ error: "You already have a pending 2nd chance request for this topic." });
    }

    const cleanReason = reason && typeof reason === "string" ? sanitize(reason).trim() : "Technical or connectivity difficulties during the exam.";
    const validCategory = ["technical", "connectivity", "interrupted", "other"].includes(category)
      ? category
      : "technical";

    const retakeRequest = await prisma.retakeRequest.create({
      data: {
        userId,
        quizId: Number(quizId),
        category: validCategory,
        reason: cleanReason,
        status: "pending",
      },
    });

    logSecurity("RETAKE_REQUESTED", `${user.username} quiz=${quiz.id} category=${validCategory}`, "", req);

    // Asynchronously dispatch notification to admin email
    sendAdminRetakeNotification({
      studentUsername: user.username,
      studentEmail: user.email,
      quizTitle: quiz.title,
      quizId: quiz.id,
      previousScore: attempt.score,
      tabSwitches: attempt.tabSwitches,
      reason: cleanReason,
      category: validCategory,
    }).catch((err) => {
      console.error("[Retake] Failed to dispatch admin notification email:", err);
    });

    res.status(201).json({
      success: true,
      message: "Your request for a 2nd chance has been submitted. The instructor will review it shortly.",
      request: retakeRequest,
    });
  } catch (error) {
    console.error("Retake request submission error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// ADMIN AUTHENTICATION MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

function verifyAdminKey(providedKey: string | undefined): boolean {
  if (!providedKey || !ADMIN_PIN) return false;

  const keyBuffer = Buffer.from(providedKey);
  const adminPinBuffer = Buffer.from(ADMIN_PIN);

  if (keyBuffer.length !== adminPinBuffer.length) {
    // Timing-attack prevention: run constant-time comparison on equal length buffers
    crypto.timingSafeEqual(adminPinBuffer, adminPinBuffer);
    return false;
  }

  return crypto.timingSafeEqual(keyBuffer, adminPinBuffer);
}

function adminMiddleware(req: Request, res: Response, next: NextFunction) {
  let key: string | undefined = undefined;

  const adminHeader = req.headers["x-admin-key"];
  if (typeof adminHeader === "string") {
    key = adminHeader.trim();
  } else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    key = req.headers.authorization.substring(7).trim();
  }

  if (!verifyAdminKey(key)) {
    logSecurity("ADMIN_AUTH_FAILED", "", `${req.method} ${req.originalUrl || req.url}`, req);
    return res.status(403).json({ error: "Invalid admin PIN" });
  }

  next();
}

// Protect all /api/admin routes with header-based admin authentication
app.use("/api/admin", adminMiddleware);

// ═══════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════

app.post("/api/admin/reset-attempt", adminLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { username, quizId } = req.body;

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

// ═══════════════════════════════════════════════════════════════
// ADMIN: RETAKE REQUESTS INBOX & 1-CLICK ACTIONS
// ═══════════════════════════════════════════════════════════════

// List all 2nd chance requests
app.get("/api/admin/retake-requests", adminLimiter, async (_req: Request, res: Response) => {
  try {
    const requests = await prisma.retakeRequest.findMany({
      include: {
        user: { select: { id: true, username: true, email: true } },
        quiz: { select: { id: true, title: true } },
      },
      orderBy: [
        { createdAt: "desc" },
      ],
    });

    // Enrich each request with attempt history
    const enriched = await Promise.all(
      requests.map(async (item) => {
        const attempt = await prisma.attempt.findFirst({
          where: { userId: item.userId, quizId: item.quizId },
          orderBy: { createdAt: "desc" },
          select: { id: true, score: true, status: true, tabSwitches: true, createdAt: true },
        });

        return {
          id: item.id,
          userId: item.userId,
          username: item.user.username,
          userEmail: item.user.email,
          quizId: item.quizId,
          quizTitle: item.quiz.title,
          category: item.category,
          reason: item.reason,
          status: item.status,
          adminNote: item.adminNote,
          createdAt: item.createdAt,
          resolvedAt: item.resolvedAt,
          attempt: attempt ? {
            score: attempt.score,
            status: attempt.status,
            tabSwitches: attempt.tabSwitches,
            createdAt: attempt.createdAt,
          } : null,
        };
      })
    );

    res.json(enriched);
  } catch (error) {
    console.error("Admin list retake requests error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 1-Click Approve Retake: sets status="approved", clears student attempt for that quiz, emails student
app.post("/api/admin/retake-requests/:requestId/approve", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { requestId } = req.params;
    const numId = Number(requestId);
    if (!Number.isInteger(numId) || numId <= 0) return res.status(400).json({ error: "Invalid request ID" });

    const retake = await prisma.retakeRequest.findUnique({
      where: { id: numId },
      include: {
        user: { select: { id: true, username: true, email: true } },
        quiz: { select: { id: true, title: true } },
      },
    });

    if (!retake) return res.status(404).json({ error: "Retake request not found" });

    // Update request status
    const updated = await prisma.retakeRequest.update({
      where: { id: numId },
      data: {
        status: "approved",
        resolvedAt: new Date(),
      },
    });

    // Clear previous attempt and answers for this student on this specific quiz
    const attempts = await prisma.attempt.findMany({
      where: { userId: retake.userId, quizId: retake.quizId },
      select: { id: true },
    });

    const attemptIds = attempts.map((a) => a.id);
    if (attemptIds.length > 0) {
      await prisma.answer.deleteMany({ where: { attemptId: { in: attemptIds } } });
      await prisma.attempt.deleteMany({ where: { id: { in: attemptIds } } });
    }

    logSecurity("ADMIN_RETAKE_APPROVED", `Request ${numId} for ${retake.user.username} on quiz ${retake.quizId}`, "", req);

    // Send confirmation email to student if email is registered
    if (retake.user.email) {
      sendStudentRetakeApproval(retake.user.email, retake.user.username, retake.quiz.title).catch((err) => {
        console.error("[Retake] Error sending student approval email:", err);
      });
    }

    res.json({
      success: true,
      message: `Retake request approved for ${retake.user.username} on "${retake.quiz.title}". Attempt lock cleared!`,
      request: updated,
    });
  } catch (error) {
    console.error("Approve retake error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Decline Retake: sets status="declined"
app.post("/api/admin/retake-requests/:requestId/decline", adminLimiter, bodySizeGuard(5), async (req: Request, res: Response) => {
  try {
    const { requestId } = req.params;
    const { note } = req.body || {};
    const numId = Number(requestId);
    if (!Number.isInteger(numId) || numId <= 0) return res.status(400).json({ error: "Invalid request ID" });

    const retake = await prisma.retakeRequest.findUnique({
      where: { id: numId },
      include: {
        user: { select: { username: true } },
        quiz: { select: { title: true } },
      },
    });

    if (!retake) return res.status(404).json({ error: "Retake request not found" });

    const updated = await prisma.retakeRequest.update({
      where: { id: numId },
      data: {
        status: "declined",
        adminNote: note ? sanitize(note).trim() : null,
        resolvedAt: new Date(),
      },
    });

    logSecurity("ADMIN_RETAKE_DECLINED", `Request ${numId} for ${retake.user.username}`, "", req);

    res.json({
      success: true,
      message: `Retake request declined for ${retake.user.username}.`,
      request: updated,
    });
  } catch (error) {
    console.error("Decline retake error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Security log viewer (admin only)
app.get("/api/admin/security-log", adminLimiter, (_req: Request, res: Response) => {
  res.json(getSecurityLog().slice(0, 100));
});

// ═══════════════════════════════════════════════════════════════
// ADMIN: QUIZ MANAGEMENT
// ═══════════════════════════════════════════════════════════════

// List all quizzes with question counts
app.get("/api/admin/quizzes", adminLimiter, async (_req: Request, res: Response) => {
  try {
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
    const { title, timeLimit } = req.body;

    if (!title || typeof title !== "string" || title.trim().length < 2) {
      return res.status(400).json({ error: "Quiz title must be at least 2 characters" });
    }
    if (!timeLimit || typeof timeLimit !== "number" || timeLimit < 30 || timeLimit > 10800) {
      return res.status(400).json({ error: "Time limit must be between 30 seconds and 3 hours" });
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

// Update an existing quiz
const updateQuizHandler = async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;
    const { title, timeLimit } = req.body || {};

    const quizIdErr = validateQuizId(quizId);
    if (quizIdErr) return res.status(400).json({ error: quizIdErr });

    const existingQuiz = await prisma.quiz.findUnique({ where: { id: Number(quizId) } });
    if (!existingQuiz) return res.status(404).json({ error: "Quiz not found" });

    const data: { title?: string; timeLimit?: number } = {};

    if (title !== undefined) {
      if (typeof title !== "string" || title.trim().length < 2) {
        return res.status(400).json({ error: "Quiz title must be at least 2 characters" });
      }
      data.title = sanitize(title).trim();
    }

    if (timeLimit !== undefined) {
      if (typeof timeLimit !== "number" || timeLimit < 30 || timeLimit > 10800) {
        return res.status(400).json({ error: "Time limit must be between 30 seconds and 3 hours" });
      }
      data.timeLimit = timeLimit;
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({ error: "Nothing to update" });
    }

    const updatedQuiz = await prisma.quiz.update({
      where: { id: Number(quizId) },
      data,
    });

    logSecurity("ADMIN_QUIZ_UPDATED", `Quiz ${quizId}: ${updatedQuiz.title}`, "", req);
    res.json({ id: updatedQuiz.id, title: updatedQuiz.title, timeLimit: updatedQuiz.timeLimit });
  } catch (error) {
    console.error("Admin update quiz error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};
app.patch("/api/admin/quizzes/:quizId", adminLimiter, bodySizeGuard(5), updateQuizHandler);
app.put("/api/admin/quizzes/:quizId", adminLimiter, bodySizeGuard(5), updateQuizHandler);

// Delete a quiz and all its questions/answers
app.delete("/api/admin/quizzes/:quizId", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { quizId } = req.params;

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
    const { text, options, correctAnswer } = req.body;

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
    const { questions } = req.body;

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
    const { text, options, correctAnswer } = req.body || {};

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
app.get("/api/admin/users", adminLimiter, async (_req: Request, res: Response) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        email: true,
        createdAt: true,
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
      email: u.email,
      createdAt: u.createdAt,
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
    const { username, email, pin } = req.body || {};

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const cleanUsername = sanitize(username).toLowerCase();
    const effectiveEmail = email ? sanitize(email).toLowerCase() : `${cleanUsername}@gmail.com`;

    const emailErr = validateEmail(effectiveEmail);
    if (emailErr) return res.status(400).json({ error: emailErr });

    const pinErr = validatePin(pin);
    if (pinErr) return res.status(400).json({ error: pinErr });

    // Check if user or email already exists
    const existing = await prisma.user.findFirst({
      where: {
        OR: [
          { username: cleanUsername },
          { email: effectiveEmail },
        ],
      },
    });
    if (existing) {
      return res.status(409).json({ error: "Username or email already exists" });
    }

    const pinHash = await bcrypt.hash(pin.trim(), 10);

    const user = await prisma.user.create({
      data: { username: cleanUsername, email: effectiveEmail, pinHash },
      select: { id: true, username: true, email: true },
    });

    logSecurity("ADMIN_USER_CREATED", `User ${user.id}: ${user.username}`, "", req);
    res.json({ id: user.id, username: user.username, email: user.email });
  } catch (error) {
    console.error("Admin create user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update an existing user
const updateUserHandler = async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const { username, email, pin } = req.body || {};

    const numUserId = Number(userId);
    if (!Number.isInteger(numUserId) || numUserId <= 0) return res.status(400).json({ error: "Invalid user ID" });

    const existingUser = await prisma.user.findUnique({ where: { id: numUserId } });
    if (!existingUser) return res.status(404).json({ error: "User not found" });

    const data: { username?: string; email?: string; pinHash?: string } = {};

    if (username !== undefined) {
      const usernameErr = validateUsername(username);
      if (usernameErr) return res.status(400).json({ error: usernameErr });
      const cleanUsername = sanitize(username).toLowerCase();

      // Check if username is already taken by another user
      if (cleanUsername !== existingUser.username) {
        const duplicate = await prisma.user.findUnique({ where: { username: cleanUsername } });
        if (duplicate) return res.status(409).json({ error: "Username already exists" });
      }
      data.username = cleanUsername;
    }

    if (email !== undefined) {
      const emailErr = validateEmail(email);
      if (emailErr) return res.status(400).json({ error: emailErr });
      const cleanEmail = sanitize(email).toLowerCase();

      if (cleanEmail !== existingUser.email) {
        const duplicate = await prisma.user.findUnique({ where: { email: cleanEmail } });
        if (duplicate) return res.status(409).json({ error: "Email already registered to another user" });
      }
      data.email = cleanEmail;
    }

    if (pin !== undefined && pin !== "") {
      const pinErr = validatePin(pin);
      if (pinErr) return res.status(400).json({ error: pinErr });
      data.pinHash = await bcrypt.hash(String(pin).trim(), 10);
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({ error: "Nothing to update" });
    }

    const updatedUser = await prisma.user.update({
      where: { id: numUserId },
      data,
      select: { id: true, username: true, email: true },
    });

    logSecurity("ADMIN_USER_UPDATED", `User ${updatedUser.id}: ${updatedUser.username}`, "", req);
    res.json({ id: updatedUser.id, username: updatedUser.username, email: updatedUser.email });
  } catch (error) {
    console.error("Admin update user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};
app.patch("/api/admin/users/:userId", adminLimiter, bodySizeGuard(5), updateUserHandler);
app.put("/api/admin/users/:userId", adminLimiter, bodySizeGuard(5), updateUserHandler);

// Delete a user and all their attempts
app.delete("/api/admin/users/:userId", adminLimiter, async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

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
        percentage: Number(a.score.toFixed(2)),
        status: a.status === "passed" || a.score >= 75 ? "Passed" : "Not Passed",
        completedAt: a.createdAt,
        answers: a.answers.map((ans) => ({
          questionId: ans.questionId,
          questionText: ans.question.text,
          options: ans.question.options,
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

  // Keep alive: ping self every 10 minutes to prevent Railway free tier spin-down
  if (isProduction) {
    const HOST = process.env.RAILWAY_PUBLIC_DOMAIN || `localhost:${PORT}`;
    const url = `http://${HOST}/health`;
    setInterval(async () => {
      try {
        await fetch(url);
        console.log("[KEEPALIVE] Self-ping OK");
      } catch {
        console.warn("[KEEPALIVE] Self-ping failed");
      }
    }, 10 * 60 * 1000);
  }
});
