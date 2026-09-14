import rateLimit from "express-rate-limit";
import { Request, Response, NextFunction } from "express";

// ═══════════════════════════════════════════════════════════════
// RATE LIMITERS
// ═══════════════════════════════════════════════════════════════

// General API: 100 requests per 15 minutes per IP
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
});

// Login: 25 attempts per 15 minutes per IP
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please wait 15 minutes." },
  skipSuccessfulRequests: true,
});

// Registration: 10 per 15 minutes per IP
export const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many registration requests. Please wait 15 minutes." },
});

// Quiz operations: 30 per minute
export const quizLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many submissions. Slow down." },
});

// Admin: 120 per 15 minutes
export const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many admin requests. Please wait." },
});

// ═══════════════════════════════════════════════════════════════
// ACCOUNT LOCKOUT (in-memory, resets on server restart)
// ═══════════════════════════════════════════════════════════════

const failedLogins = new Map<string, { count: number; lockedUntil: number }>();
const MAX_FAILED = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

export function isAccountLocked(username: string): boolean {
  const record = failedLogins.get(username);
  if (!record) return false;
  if (Date.now() > record.lockedUntil) {
    failedLogins.delete(username);
    return false;
  }
  return true;
}

export function recordFailedLogin(username: string): void {
  const record = failedLogins.get(username) || { count: 0, lockedUntil: 0 };
  record.count++;
  if (record.count >= MAX_FAILED) {
    record.lockedUntil = Date.now() + LOCKOUT_MS;
    logSecurity("ACCOUNT_LOCKED", username, "Too many failed attempts");
  }
  failedLogins.set(username, record);
}

export function clearFailedLogins(username: string): void {
  failedLogins.delete(username);
}

// ═══════════════════════════════════════════════════════════════
// SECURITY EVENT LOGGER
// ═══════════════════════════════════════════════════════════════

interface SecurityEvent {
  timestamp: string;
  event: string;
  details: string;
  extra: string;
  ip: string;
  userAgent: string;
}

const securityLog: SecurityEvent[] = [];
const MAX_LOG_SIZE = 1000;

export function logSecurity(event: string, details: string, extra: string = "", req?: Request) {
  const entry: SecurityEvent = {
    timestamp: new Date().toISOString(),
    event,
    details,
    extra,
    ip: req ? (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "unknown" : "system",
    userAgent: req ? (req.headers["user-agent"] || "unknown") as string : "system",
  };

  securityLog.unshift(entry);
  if (securityLog.length > MAX_LOG_SIZE) securityLog.pop();

  // Also print to console with color
  const red = "\x1b[31m";
  const yellow = "\x1b[33m";
  const cyan = "\x1b[36m";
  const reset = "\x1b[0m";
  const color = event.includes("LOCKED") || event.includes("FAILED") ? red :
                event.includes("WARNING") ? yellow : cyan;
  console.log(`${color}[SECURITY] ${event}: ${details} ${extra ? `(${extra})` : ""}${reset}`);
}

export function getSecurityLog(): SecurityEvent[] {
  return securityLog;
}

// ═══════════════════════════════════════════════════════════════
// INPUT VALIDATION
// ═══════════════════════════════════════════════════════════════

export function validateUsername(username: any): string | null {
  if (!username || typeof username !== "string") return "Username is required";
  const trimmed = username.trim();
  if (trimmed.length < 2) return "Username must be at least 2 characters";
  if (trimmed.length > 50) return "Username must be 50 characters or less";
  if (!/^[a-zA-Z0-9._-]+$/.test(trimmed)) return "Username can only contain letters, numbers, dots, hyphens, underscores";
  return null;
}

export function validatePin(pin: any): string | null {
  if (!pin || typeof pin !== "string") return "PIN is required";
  if (!/^\d{5}$/.test(pin.trim())) return "PIN must be exactly 5 digits";
  return null;
}

export function validateEmail(email: any): string | null {
  if (!email || typeof email !== "string") return "Email is required";
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length > 254) return "Email is too long";
  // Enforce strictly @gmail.com
  const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
  if (!gmailRegex.test(trimmed)) {
    return "Registration is currently restricted to valid @gmail.com addresses";
  }
  return null;
}

export function validateRetakeReason(reason: any): string | null {
  if (reason === undefined || reason === null || reason === "") return null; // Optional
  if (typeof reason !== "string") return "Explanation must be text";
  if (reason.length > 1000) return "Explanation exceeds maximum length of 1,000 characters";
  const words = reason.trim().split(/\s+/).filter(Boolean);
  if (words.length > 200) return "Explanation exceeds maximum word limit of 200 words";
  return null;
}

export function validateAdminPin(pin: any): string | null {
  if (!pin || typeof pin !== "string") return "Admin PIN is required";
  if (pin.length > 100) return "Invalid admin PIN";
  return null;
}

export function validateQuizId(id: any): string | null {
  const num = Number(id);
  if (!Number.isInteger(num) || num <= 0) return "Invalid quiz ID";
  return null;
}

export function validateSelectedOption(opt: any): string | null {
  const num = Number(opt);
  if (!Number.isInteger(num) || num < 1 || num > 4) return "Selected option must be 1-4";
  return null;
}

// ═══════════════════════════════════════════════════════════════
// SANITIZATION
// ═══════════════════════════════════════════════════════════════

export function sanitize(input: any): string {
  if (typeof input !== "string") return "";
  return input
    .trim()
    .replace(/[<>]/g, "")  // strip angle brackets (XSS)
    .slice(0, 1000);        // max length safety
}

// ═══════════════════════════════════════════════════════════════
// BODY SIZE CHECK
// ═══════════════════════════════════════════════════════════════

export function bodySizeGuard(maxKB: number = 10) {
  return (req: Request, res: Response, next: NextFunction) => {
    const bodyStr = JSON.stringify(req.body || {});
    if (bodyStr.length > maxKB * 1024) {
      logSecurity("OVERSIZED_REQUEST", `Size: ${bodyStr.length} bytes`, "", req);
      return res.status(413).json({ error: "Request body too large" });
    }
    next();
  };
}

// ═══════════════════════════════════════════════════════════════
// SECURITY HEADERS
// ═══════════════════════════════════════════════════════════════

export function extraSecurityHeaders(req: Request, res: Response, next: NextFunction) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
}
