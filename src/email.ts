import nodemailer, { Transporter } from "nodemailer";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";

dotenv.config();

const SMTP_HOST = (process.env.SMTP_HOST || "smtp.gmail.com").trim();
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "465", 10);
const SMTP_USER = (process.env.SMTP_USER || "").trim();
const SMTP_PASS = (process.env.SMTP_PASS || "").replace(/\s+/g, "");
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || process.env.ADMIN_NOTIFICATION_EMAIL || SMTP_USER || "admin@quizshield.com").trim();
const FRONTEND_URL = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");

const isSmtpConfigured = Boolean(SMTP_USER && SMTP_PASS && SMTP_USER !== "your-gmail@gmail.com");

let transporter: Transporter | null = null;

if (isSmtpConfigured) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
  console.log(`[Email Service] Configured live SMTP transport with user: ${SMTP_USER}`);
} else {
  console.log(
    `[Email Service] Live SMTP credentials not configured (SMTP_USER/SMTP_PASS in .env). Email service operating in mock console mode.`
  );
}

// Locate local QuizShield logo for inline CID attachment
const logoPath = path.resolve(__dirname, "../../frontend/public/quizshield_logo.png");
const hasLogo = fs.existsSync(logoPath);

/**
 * Helper to dispatch an email via Nodemailer or fall back to rich console mock logging
 */
async function dispatchEmail(options: {
  to: string;
  subject: string;
  html: string;
  textFallback: string;
}): Promise<boolean> {
  if (transporter && isSmtpConfigured) {
    try {
      const info = await transporter.sendMail({
        from: `"QuizShield Platform" <${SMTP_USER}>`,
        to: options.to,
        subject: options.subject,
        html: options.html,
        text: options.textFallback,
        headers: {
          "X-Entity-Ref-ID": `${Date.now()}`,
        },
      });
      console.log(`[Email Service] Email sent successfully to ${options.to}. MessageId: ${info.messageId}`);
      return true;
    } catch (err: any) {
      console.error(`[Email Service Error] Failed to send email to ${options.to}:`, err.message);
      return false;
    }
  } else {
    // Mock logger for seamless local testing & demonstration
    console.log("\n=======================================================");
    console.log(`📨 [MOCK EMAIL DISPATCH] To: ${options.to}`);
    console.log(`📌 Subject: ${options.subject}`);
    console.log("-------------------------------------------------------");
    console.log(options.textFallback);
    console.log("=======================================================\n");
    return true;
  }
}

/**
 * Common shared HTML email wrapper ensuring cross-client styling and brand alignment
 */
function emailWrapper(accentColor: string, badgeText: string, contentHtml: string): string {
  const logoHtml = `
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="42" height="42" style="width: 42px; height: 42px; border-radius: 10px; background-color: #064e3b; border: 1.5px solid ${accentColor}; text-align: center;">
      <tr>
        <td align="center" valign="middle" style="font-size: 22px; line-height: 42px; text-align: center;">
          🛡️
        </td>
      </tr>
    </table>
  `;

  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>QuizShield Security Notification</title>
        <style>
          body { margin: 0; padding: 0; background-color: #050811; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
          table { border-collapse: separate; }
          a { text-decoration: none; }
        </style>
      </head>
      <body style="margin: 0; padding: 32px 12px; background-color: #050811; color: #f1f5f9;">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td align="center">
              <!-- Main Card Container -->
              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 580px; background-color: #0b0f19; border: 1px solid #1e293b; border-top: 4px solid ${accentColor}; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
                
                <!-- Brand Header -->
                <tr>
                  <td style="padding: 24px 28px; background-color: #0c1222; border-bottom: 1px solid #1a2333;">
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                        <td width="48" valign="middle">
                          ${logoHtml}
                        </td>
                        <td style="padding-left: 14px;" valign="middle">
                          <span style="font-size: 19px; font-weight: 800; letter-spacing: 0.5px; color: #ffffff; display: block;">QuizShield</span>
                          <span style="font-size: 11px; font-weight: 600; letter-spacing: 0.8px; color: #94a3b8; text-transform: uppercase; display: block; margin-top: 2px;">Examination Integrity System</span>
                        </td>
                        <td align="right" valign="middle">
                          <span style="display: inline-block; background-color: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); color: ${accentColor}; font-size: 10px; font-weight: 700; letter-spacing: 0.8px; padding: 4px 10px; border-radius: 20px; text-transform: uppercase;">
                            ${badgeText}
                          </span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <!-- Content Area -->
                <tr>
                  <td style="padding: 32px 28px;">
                    ${contentHtml}
                  </td>
                </tr>

                <!-- Official Footer -->
                <tr>
                  <td style="padding: 20px 28px; background-color: #080c14; border-top: 1px solid #151d2e; text-align: center;">
                    <p style="margin: 0; font-size: 12px; font-weight: 600; color: #64748b; letter-spacing: 0.3px;">
                      QuizShield Platform &bull; Automated Security Dispatch
                    </p>
                    <p style="margin: 6px 0 0 0; font-size: 11px; color: #475569; line-height: 1.5;">
                      This notification was delivered to verify examination access. Do not share your 5-digit PIN with anyone.
                    </p>
                    <p style="margin: 8px 0 0 0; font-size: 10px; color: #334155;">
                      &copy; ${new Date().getFullYear()} QuizShield Examination Division. All rights reserved.
                    </p>
                  </td>
                </tr>

              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;
}

/**
 * Sends student their generated 5-digit PIN and credentials upon registration
 */
export async function sendWelcomeEmail(
  toEmail: string,
  username: string,
  pin: string
): Promise<boolean> {
  const subject = `QuizShield: Your 5-Digit Login PIN (${username})`;
  const textFallback = `Welcome to QuizShield, ${username}!\n\nYour examination account is ready.\n\nUsername: ${username}\nRegistered Email: ${toEmail}\nYour 5-Digit PIN: ${pin}\n\nLogin URL: ${FRONTEND_URL}/login\n\nExamination Protocols:\n- Exactly 1 attempt is permitted per chapter quiz topic.\n- Real-time tab monitoring is active during assessments.\n- Keep your credentials confidential.\n\nGood luck with your exams!`;

  const pinDigits = pin.split("");

  const contentHtml = `
    <h2 style="margin: 0 0 8px 0; font-size: 22px; font-weight: 700; color: #ffffff; letter-spacing: -0.3px;">
      Welcome to the Platform, ${username}!
    </h2>
    <p style="margin: 0 0 24px 0; font-size: 14px; color: #94a3b8; line-height: 1.6;">
      Your student examination account has been registered. Use your unique username and 5-digit PIN to authenticate into the examination portal.
    </p>

    <!-- Candidate Access Card -->
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; margin-bottom: 24px; overflow: hidden;">
      <tr>
        <td style="padding: 16px 20px; background-color: #131d33; border-bottom: 1px solid #1e293b;">
          <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
              <td style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #10b981;">
                🔒 Candidate Examination Keycard
              </td>
              <td align="right" style="font-size: 11px; color: #64748b; font-family: monospace;">
                STATUS: ACTIVE
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding: 24px 20px; text-align: center;">
          <div style="font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 14px;">
            Your 5-Digit Login PIN
          </div>
          
          <!-- Segmented PIN Digits -->
          <table role="presentation" border="0" cellpadding="0" cellspacing="0" align="center" style="margin: 0 auto 14px auto;">
            <tr>
              ${pinDigits
                .map(
                  (digit) => `
                <td style="padding: 0 5px;">
                  <div style="width: 44px; height: 52px; background-color: #0b1120; border: 1.5px solid #10b981; border-radius: 8px; font-family: 'SF Mono', Consolas, Monaco, monospace; font-size: 26px; font-weight: 800; color: #34d399; line-height: 52px; text-align: center; box-shadow: 0 4px 14px rgba(16, 185, 129, 0.15);">
                    ${digit}
                  </div>
                </td>
              `
                )
                .join("")}
            </tr>
          </table>

          <div style="font-size: 12px; color: #64748b; margin-top: 8px;">
            Candidate Username: <strong style="color: #f1f5f9;">${username}</strong>
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding: 12px 20px; background-color: #0b1120; border-top: 1px solid #1e293b; text-align: center;">
          <span style="font-size: 11px; color: #94a3b8;">
            Registered Email: <span style="color: #e2e8f0;">${toEmail}</span>
          </span>
        </td>
      </tr>
    </table>

    <!-- Call to Action Button -->
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 28px 0;">
      <tr>
        <td align="center">
          <a href="${FRONTEND_URL}/login" target="_blank" style="display: inline-block; background-color: #059669; background-image: linear-gradient(135deg, #059669 0%, #047857 100%); border: 1px solid #10b981; padding: 13px 36px; border-radius: 10px; font-size: 14px; font-weight: 700; letter-spacing: 0.4px; color: #ffffff; text-decoration: none; box-shadow: 0 6px 20px rgba(16, 185, 129, 0.3);">
            Access Examination Portal &rarr;
          </a>
        </td>
      </tr>
    </table>

    <!-- Examination Protocol Rules -->
    <div style="background-color: #0d1527; border: 1px solid #1a263e; border-radius: 10px; padding: 18px 20px; margin-top: 24px;">
      <div style="font-size: 12px; font-weight: 700; color: #10b981; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 12px;">
        &bull; Examination Security Protocols
      </div>
      <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
        <tr>
          <td width="20" valign="top" style="color: #10b981; font-weight: bold;">1.</td>
          <td style="padding-bottom: 8px;"><strong style="color: #e2e8f0;">Strict 1 Attempt Per Topic:</strong> Each chapter quiz allows exactly one attempt. Plan your test session carefully.</td>
        </tr>
        <tr>
          <td width="20" valign="top" style="color: #10b981; font-weight: bold;">2.</td>
          <td style="padding-bottom: 8px;"><strong style="color: #e2e8f0;">Anti-Cheat Monitoring:</strong> Switching browser tabs or minimizing windows records violation flags and can trigger auto-submission.</td>
        </tr>
        <tr>
          <td width="20" valign="top" style="color: #10b981; font-weight: bold;">3.</td>
          <td><strong style="color: #e2e8f0;">2nd Chance Appeal System:</strong> If an unexpected network drop or hardware issue occurs, submit an appeal from your dashboard for administrator review.</td>
        </tr>
      </table>
    </div>
  `;

  const html = emailWrapper("#10b981", "Credentials Issued", contentHtml);
  return dispatchEmail({ to: toEmail, subject, html, textFallback });
}

/**
 * Notifies the administrator when a student submits a 2nd chance request
 */
export async function sendAdminRetakeNotification(details: {
  studentUsername: string;
  studentEmail?: string | null;
  quizTitle: string;
  quizId: number;
  previousScore: number;
  tabSwitches: number;
  reason: string;
  category: string;
}): Promise<boolean> {
  const safeEmail = details.studentEmail || "No email registered";
  const subject = `QuizShield Retake Appeal: ${details.studentUsername} - ${details.quizTitle}`;
  const textFallback = `New 2nd Chance Retake Request Submitted:\n\nCandidate: ${details.studentUsername} (${safeEmail})\nQuiz Topic: ${details.quizTitle} (ID: ${details.quizId})\nPrevious Score: ${details.previousScore}%\nTab Switch Violations: ${details.tabSwitches}\nCategory: ${details.category}\n\nCandidate Statement:\n"${details.reason}"\n\nAdmin Review URL: ${FRONTEND_URL}/admin\nPlease log in to review and approve or decline.`;

  const contentHtml = `
    <h2 style="margin: 0 0 8px 0; font-size: 21px; font-weight: 700; color: #ffffff;">
      2nd Chance Appeal Submitted
    </h2>
    <p style="margin: 0 0 20px 0; font-size: 14px; color: #94a3b8; line-height: 1.5;">
      A student candidate has filed a formal appeal requesting an attempt reset for a completed examination topic.
    </p>

    <!-- Incident Summary Table -->
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 10px; margin-bottom: 20px; font-size: 13px;">
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #64748b; font-weight: 600; width: 35%;">Candidate</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #f1f5f9; font-weight: 700;">
          ${details.studentUsername} <span style="font-weight: normal; color: #94a3b8;">(${details.studentEmail})</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #64748b; font-weight: 600;">Examination Topic</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #34d399; font-weight: 700;">
          ${details.quizTitle} <span style="color: #64748b; font-weight: normal;">(ID: ${details.quizId})</span>
        </td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #64748b; font-weight: 600;">Recorded Score</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #f1f5f9; font-weight: 700;">
          ${details.previousScore}%
        </td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; color: #64748b; font-weight: 600;">Tab Switches</td>
        <td style="padding: 10px 16px; border-bottom: 1px solid #1e293b; font-weight: 700; color: ${details.tabSwitches > 0 ? "#f87171" : "#10b981"};">
          ${details.tabSwitches} ${details.tabSwitches === 1 ? "violation" : "violations"}
        </td>
      </tr>
      <tr>
        <td style="padding: 10px 16px; color: #64748b; font-weight: 600;">Issue Category</td>
        <td style="padding: 10px 16px; color: #f59e0b; font-weight: 700; text-transform: uppercase;">
          ${details.category}
        </td>
      </tr>
    </table>

    <!-- Student Explanation Statement -->
    <div style="margin-bottom: 24px;">
      <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 8px;">
        Candidate's Written Explanation:
      </div>
      <div style="background-color: #131d33; border-left: 3px solid #f59e0b; border-radius: 4px; padding: 14px 16px; font-size: 13px; color: #e2e8f0; line-height: 1.6; font-style: italic;">
        "${details.reason}"
      </div>
    </div>

    <!-- Action Button -->
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 20px 0;">
      <tr>
        <td align="center">
          <a href="${FRONTEND_URL}/admin" target="_blank" style="display: inline-block; background-color: #d97706; background-image: linear-gradient(135deg, #d97706 0%, #b45309 100%); border: 1px solid #f59e0b; padding: 12px 30px; border-radius: 8px; font-size: 14px; font-weight: 700; color: #ffffff; text-decoration: none; box-shadow: 0 4px 16px rgba(217, 119, 6, 0.3);">
            Review in Admin Appeals Tab &rarr;
          </a>
        </td>
      </tr>
    </table>
  `;

  const html = emailWrapper("#f59e0b", "Action Required", contentHtml);
  return dispatchEmail({ to: ADMIN_EMAIL, subject, html, textFallback });
}

/**
 * Notifies the student that their retake request was approved
 */
export async function sendStudentRetakeApproval(
  toEmail: string | null | undefined,
  username: string,
  quizTitle: string
): Promise<boolean> {
  if (!toEmail) {
    console.log(`[Email Service] Student ${username} has no registered email. Skipping retake approval email.`);
    return false;
  }
  const subject = `QuizShield: 2nd Chance Approved for ${quizTitle}`;
  const textFallback = `Hello ${username},\n\nYour request for a 2nd attempt on "${quizTitle}" has been APPROVED by the administrator.\nYour previous attempt records have been reset.\n\nDashboard URL: ${FRONTEND_URL}/dashboard\nYou may now log in to QuizShield and attempt the quiz again.\n\nGood luck!`;

  const contentHtml = `
    <h2 style="margin: 0 0 8px 0; font-size: 22px; font-weight: 700; color: #ffffff;">
      2nd Chance Appeal Approved!
    </h2>
    <p style="margin: 0 0 20px 0; font-size: 14px; color: #94a3b8; line-height: 1.6;">
      Hello <strong style="color: #f1f5f9;">${username}</strong>, your formal appeal for a retake on the topic below has been reviewed and granted by the examination administrator.
    </p>

    <!-- Clearance Card -->
    <div style="background-color: #0f172a; border: 1.5px solid #10b981; border-radius: 12px; padding: 22px 20px; text-align: center; margin-bottom: 24px; box-shadow: 0 6px 20px rgba(16, 185, 129, 0.12);">
      <div style="font-size: 11px; font-weight: 700; letter-spacing: 1px; color: #10b981; text-transform: uppercase; margin-bottom: 6px;">
        Examination Lock Cleared
      </div>
      <div style="font-size: 19px; font-weight: 800; color: #ffffff; margin-bottom: 6px;">
        ${quizTitle}
      </div>
      <div style="font-size: 12px; color: #94a3b8;">
        Prior attempt records have been cleared &bull; Eligible for 1 new attempt
      </div>
    </div>

    <!-- Action Button -->
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="margin: 24px 0;">
      <tr>
        <td align="center">
          <a href="${FRONTEND_URL}/dashboard" target="_blank" style="display: inline-block; background-color: #059669; background-image: linear-gradient(135deg, #059669 0%, #047857 100%); border: 1px solid #10b981; padding: 13px 36px; border-radius: 10px; font-size: 14px; font-weight: 700; color: #ffffff; text-decoration: none; box-shadow: 0 6px 20px rgba(16, 185, 129, 0.25);">
            Launch Chapter Quiz Now &rarr;
          </a>
        </td>
      </tr>
    </table>

    <p style="font-size: 12px; color: #64748b; line-height: 1.5; text-align: center; margin: 0;">
      Please ensure you have a stable network connection before starting. Tab switches are strictly monitored.
    </p>
  `;

  const html = emailWrapper("#10b981", "Appeal Granted", contentHtml);
  return dispatchEmail({ to: toEmail, subject, html, textFallback });
}
