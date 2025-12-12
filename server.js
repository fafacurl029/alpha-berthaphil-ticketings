const express = require("express");
const path = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { z } = require("zod");
const { PrismaClient } = require("@prisma/client");
require("dotenv").config();

const prisma = new PrismaClient();
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "";
const BOOTSTRAP_TOKEN = process.env.BOOTSTRAP_TOKEN || "";
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

if (!JWT_SECRET) {
  console.warn("WARN: JWT_SECRET is not set. Set it in Render Environment variables.");
}

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// Static frontend
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// --- Helpers ---
const Roles = ["EMPLOYEE", "L1", "L2", "L3", "SUPERVISOR", "ADMIN"];
const Teams = ["SERVICE_DESK", "NETWORK", "SYSTEMS", "SECURITY", "APPLICATION", "FIELD"];
const Shifts = ["MORNING", "MID", "NIGHT", "WEEKEND", "ONCALL"];
const Statuses = ["NEW","ASSIGNED","IN_PROGRESS","WAITING_ON_USER","WAITING_ON_VENDOR","ESCALATED","RESOLVED","CLOSED"];
const Priorities = ["P1","P2","P3","P4"];
const Impacts = ["LOW","MEDIUM","HIGH"];
const Urgencies = ["LOW","MEDIUM","HIGH"];

function now() { return new Date(); }

function safeUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, team: u.team, shift: u.shift, active: u.active };
}

function signSession(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
}

function setSessionCookie(res, token) {
  res.cookie("ab_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: 12 * 60 * 60 * 1000
  });
}

function clearSessionCookie(res) {
  res.clearCookie("ab_session");
}

function authRequired(req, res, next) {
  const token = req.cookies.ab_session;
  if (!token) return res.status(401).json({ message: "Not authenticated" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = payload;
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid session" });
  }
}

function requireRole(...allowed) {
  return (req, res, next) => {
    const role = req.auth?.role;
    if (!role || !allowed.includes(role)) return res.status(403).json({ message: "Forbidden" });
    next();
  };
}

function roleLevel(role) {
  // for comparisons
  if (role === "ADMIN") return 99;
  if (role === "SUPERVISOR") return 50;
  if (role === "L3") return 30;
  if (role === "L2") return 20;
  if (role === "L1") return 10;
  return 1; // EMPLOYEE
}

function currentShiftPH() {
  // Asia/Manila fixed UTC+8 (no DST). Use server time but treat as UTC+8.
  const d = new Date();
  // convert to UTC+8
  const utc = d.getTime() + d.getTimezoneOffset() * 60000;
  const ph = new Date(utc + 8 * 3600000);
  const day = ph.getDay(); // 0 Sun
  const hour = ph.getHours();

  const isWeekend = day === 0 || day === 6;
  if (isWeekend) return "WEEKEND";
  // MORNING 06-14, MID 14-22, NIGHT 22-06
  if (hour >= 6 && hour < 14) return "MORNING";
  if (hour >= 14 && hour < 22) return "MID";
  return "NIGHT";
}

function isShiftActive(userShift) {
  const cur = currentShiftPH();
  if (userShift === "ONCALL") return true;
  if (cur === "WEEKEND") return userShift === "WEEKEND" || userShift === "ONCALL";
  return userShift === cur || userShift === "ONCALL";
}

function computePriority(impact, urgency) {
  // simple matrix
  const I = impact, U = urgency;
  if (I === "HIGH" && U === "HIGH") return "P1";
  if (I === "HIGH" && (U === "MEDIUM" || U === "LOW")) return "P2";
  if (I === "MEDIUM" && U === "HIGH") return "P2";
  if (I === "MEDIUM" && U === "MEDIUM") return "P3";
  if (I === "LOW" && U === "HIGH") return "P3";
  return "P4";
}

function slaPolicy(priority) {
  // minutes for first response and resolution
  switch (priority) {
    case "P1": return { fr: 15, res: 4 * 60 };
    case "P2": return { fr: 60, res: 8 * 60 };
    case "P3": return { fr: 4 * 60, res: 2 * 24 * 60 };
    default:   return { fr: 24 * 60, res: 5 * 24 * 60 };
  }
}

function addMinutes(date, minutes) {
  return new Date(date.getTime() + minutes * 60000);
}

function teamForCategory(category) {
  const c = (category || "").toLowerCase();
  if (c.includes("network") || c.includes("vpn") || c.includes("wifi")) return "NETWORK";
  if (c.includes("security") || c.includes("mfa") || c.includes("antivirus")) return "SECURITY";
  if (c.includes("hardware") || c.includes("laptop") || c.includes("pc") || c.includes("printer")) return "FIELD";
  if (c.includes("system") || c.includes("server") || c.includes("active directory")) return "SYSTEMS";
  if (c.includes("app") || c.includes("software")) return "APPLICATION";
  return "SERVICE_DESK";
}

function requiredLevelForCategory(category) {
  // by default: L1 first, technicians can escalate
  const team = teamForCategory(category);
  if (team === "SECURITY") return "L2";
  if (team === "NETWORK") return "L2";
  return "L1";
}


async function pickAssignee(tx, role, team){
  const candidates = await tx.user.findMany({
    where: { active: true, role, team }
  });
  const activeCandidates = candidates.filter(u => isShiftActive(u.shift));
  if (!activeCandidates.length) return null;

  const counts = await Promise.all(activeCandidates.map(async (u) => {
    const openCount = await tx.ticket.count({
      where: {
        assignedToId: u.id,
        status: { in: ["NEW","ASSIGNED","IN_PROGRESS","WAITING_ON_USER","WAITING_ON_VENDOR","ESCALATED"] }
      }
    });
    return { id: u.id, openCount };
  }));
  counts.sort((a,b)=> a.openCount - b.openCount);
  return counts[0].id;
}

async function logAudit(actorId, action, details, ticketId=null) {
  await prisma.auditLog.create({
    data: {
      actorId,
      action,
      details,
      ticketId
    }
  });
}

// --- Meta ---
app.get("/api/meta", (req, res) => {
  res.json({
    roles: Roles,
    teams: Teams,
    shifts: Shifts,
    statuses: Statuses,
    priorities: Priorities,
    impacts: Impacts,
    urgencies: Urgencies,
    currentShiftPH: currentShiftPH(),
  });
});

// --- Setup (bootstrap admin) ---
app.post("/api/setup/bootstrap", async (req, res) => {
  const schema = z.object({
    token: z.string().min(8),
    name: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8)
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });
  const { token, name, email, password } = parsed.data;

  if (!BOOTSTRAP_TOKEN || token !== BOOTSTRAP_TOKEN) {
    return res.status(403).json({ message: "Invalid bootstrap token" });
  }

  const adminExists = await prisma.user.findFirst({ where: { role: "ADMIN" } });
  if (adminExists) return res.status(409).json({ message: "Admin already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const admin = await prisma.user.create({
    data: { name, email, passwordHash, role: "ADMIN", team: "SERVICE_DESK", shift: "MORNING", active: true }
  });

  await logAudit(admin.id, "BOOTSTRAP_ADMIN_CREATED", { email }, null);

  const session = signSession(admin);
  setSessionCookie(res, session);
  res.json({ user: safeUser(admin) });
});

// --- Auth ---
app.post("/api/auth/login", async (req, res) => {
  const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input" });

  const { email, password } = parsed.data;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.active) return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const token = signSession(user);
  setSessionCookie(res, token);
  await logAudit(user.id, "LOGIN", { }, null);
  res.json({ user: safeUser(user) });
});

app.post("/api/auth/logout", authRequired, async (req, res) => {
  await logAudit(req.auth.sub, "LOGOUT", {}, null);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!user) return res.status(401).json({ message: "Not authenticated" });
  res.json({ user: safeUser(user) });
});

// --- Users (Admin) ---
app.get("/api/users", authRequired, requireRole("ADMIN"), async (req, res) => {
  const users = await prisma.user.findMany({ orderBy: { createdAt: "desc" } });
  res.json({ users: users.map(safeUser) });
});

app.post("/api/users", authRequired, requireRole("ADMIN"), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    role: z.enum(["EMPLOYEE","L1","L2","L3","SUPERVISOR","ADMIN"]),
    team: z.enum(["SERVICE_DESK","NETWORK","SYSTEMS","SECURITY","APPLICATION","FIELD"]),
    shift: z.enum(["MORNING","MID","NIGHT","WEEKEND","ONCALL"]),
    password: z.string().min(8)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });

  const data = parsed.data;
  const passwordHash = await bcrypt.hash(data.password, 10);
  const user = await prisma.user.create({
    data: { name: data.name, email: data.email, passwordHash, role: data.role, team: data.team, shift: data.shift, active: true }
  });

  await logAudit(req.auth.sub, "USER_CREATED", { userId: user.id, email: user.email, role: user.role }, null);
  res.json({ user: safeUser(user) });
});

app.patch("/api/users/:id", authRequired, requireRole("ADMIN"), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2).optional(),
    role: z.enum(["EMPLOYEE","L1","L2","L3","SUPERVISOR","ADMIN"]).optional(),
    team: z.enum(["SERVICE_DESK","NETWORK","SYSTEMS","SECURITY","APPLICATION","FIELD"]).optional(),
    shift: z.enum(["MORNING","MID","NIGHT","WEEKEND","ONCALL"]).optional(),
    active: z.boolean().optional()
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });

  const user = await prisma.user.update({ where: { id: req.params.id }, data: parsed.data });
  await logAudit(req.auth.sub, "USER_UPDATED", { userId: user.id }, null);
  res.json({ user: safeUser(user) });
});

app.post("/api/users/:id/reset-password", authRequired, requireRole("ADMIN"), async (req, res) => {
  const schema = z.object({ password: z.string().min(8) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input" });

  const passwordHash = await bcrypt.hash(parsed.data.password, 10);
  await prisma.user.update({ where: { id: req.params.id }, data: { passwordHash } });
  await logAudit(req.auth.sub, "USER_PASSWORD_RESET", { userId: req.params.id }, null);
  res.json({ ok: true });
});

// --- Tickets ---
app.post("/api/tickets", authRequired, async (req, res) => {
  const schema = z.object({
    subject: z.string().min(3),
    description: z.string().min(3),
    category: z.string().min(2),
    subcategory: z.string().min(1),
    impact: z.enum(["LOW","MEDIUM","HIGH"]),
    urgency: z.enum(["LOW","MEDIUM","HIGH"])
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });

  const requester = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!requester || !requester.active) return res.status(401).json({ message: "Not authenticated" });

  const priority = computePriority(parsed.data.impact, parsed.data.urgency);
  const assignedTeam = teamForCategory(parsed.data.category);
  const requiredLevel = requiredLevelForCategory(parsed.data.category);

  const policy = slaPolicy(priority);
  const createdAt = now();
  const slaFirstResponseDue = addMinutes(createdAt, policy.fr);
  const slaResolutionDue = addMinutes(createdAt, policy.res);

  const result = await prisma.$transaction(async (tx) => {
    const counter = await tx.ticketCounter.update({
      where: { id: 1 },
      data: { nextNo: { increment: 1 } }
    });

    const ticketNo = counter.nextNo; // uses pre-incremented value
    const humanId = `AB-${String(ticketNo).padStart(6, "0")}`;

    // auto-assign to an active agent on the required level/team (shift-aware, least-loaded)
let assignedToId = null;
let status = "NEW";

if (requiredLevel === "L1") {
  assignedToId = await pickAssignee(tx, "L1", assignedTeam);
} else if (requiredLevel === "L2") {
  assignedToId = await pickAssignee(tx, "L2", assignedTeam);
} else if (requiredLevel === "L3") {
  assignedToId = await pickAssignee(tx, "L3", assignedTeam);
}

if (assignedToId) status = "ASSIGNED";

const t = await tx.ticket.create({
      data: {
        ticketNo,
        humanId,
        subject: parsed.data.subject,
        description: parsed.data.description,
        category: parsed.data.category,
        subcategory: parsed.data.subcategory,
        impact: parsed.data.impact,
        urgency: parsed.data.urgency,
        priority,
        status,
        requesterId: requester.id,
        assignedToId,
        requiredLevel,
        assignedTeam,
        slaFirstResponseDue,
        slaResolutionDue
      }
    });

    await tx.auditLog.create({
      data: { actorId: requester.id, action: "TICKET_CREATED", details: { humanId }, ticketId: t.id }
    });

    return t;
  });

  const ticket = await prisma.ticket.findUnique({
    where: { id: result.id },
    include: { requester: true, assignedTo: true }
  });

  res.json({ ticket });
});

app.get("/api/tickets", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });

  const q = (req.query.q || "").toString().trim();
  const status = (req.query.status || "").toString().trim();
  const priority = (req.query.priority || "").toString().trim();
  const mine = (req.query.mine || "").toString().trim() === "1";

  const where = {};

  if (me.role === "EMPLOYEE") {
    where.requesterId = me.id;
  } else {
    if (mine) where.assignedToId = me.id;
  }

  if (status && Statuses.includes(status)) where.status = status;
  if (priority && Priorities.includes(priority)) where.priority = priority;
  if (q) {
    where.OR = [
      { humanId: { contains: q, mode: "insensitive" } },
      { subject: { contains: q, mode: "insensitive" } },
      { category: { contains: q, mode: "insensitive" } }
    ];
  }

  const tickets = await prisma.ticket.findMany({
    where,
    orderBy: { updatedAt: "desc" },
    include: { requester: true, assignedTo: true }
  });

  res.json({ tickets });
});

app.get("/api/tickets/:id", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });

  const ticket = await prisma.ticket.findUnique({
    where: { id: req.params.id },
    include: {
      requester: true,
      assignedTo: true,
      comments: { include: { author: true }, orderBy: { createdAt: "asc" } },
      auditLogs: { include: { actor: true }, orderBy: { createdAt: "desc" } }
    }
  });

  if (!ticket) return res.status(404).json({ message: "Not found" });
  if (me.role === "EMPLOYEE" && ticket.requesterId !== me.id) return res.status(403).json({ message: "Forbidden" });

  res.json({ ticket });
});

app.patch("/api/tickets/:id", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });

  if (me.role === "EMPLOYEE") return res.status(403).json({ message: "Forbidden" });

  const schema = z.object({
    status: z.enum(["NEW","ASSIGNED","IN_PROGRESS","WAITING_ON_USER","WAITING_ON_VENDOR","ESCALATED","RESOLVED","CLOSED"]).optional(),
    priority: z.enum(["P1","P2","P3","P4"]).optional(),
    assignedToId: z.string().optional().nullable(),
    slaPaused: z.boolean().optional(),
    slaPauseReason: z.string().optional().nullable()
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });

  // enforcement
  const data = { ...parsed.data };

  if (data.priority && roleLevel(me.role) < roleLevel("L2")) {
    return res.status(403).json({ message: "Only L2/L3/Admin can change priority" });
  }

  if (data.status === "CLOSED" && roleLevel(me.role) < roleLevel("L3")) {
    return res.status(403).json({ message: "Only L3/Admin can close tickets" });
  }

  if (data.status === "RESOLVED") {
    data.resolvedAt = now();
  }
  if (data.status === "CLOSED") {
    data.closedAt = now();
  }

  const updated = await prisma.ticket.update({ where: { id: req.params.id }, data });

  // first response tracking: when IT sets IN_PROGRESS or adds first internal/public comment handled elsewhere
  if (!updated.firstRespondedAt && (data.status === "IN_PROGRESS" || data.status === "ASSIGNED")) {
    await prisma.ticket.update({ where: { id: updated.id }, data: { firstRespondedAt: now() } });
  }

  await logAudit(me.id, "TICKET_UPDATED", { changes: data }, updated.id);

  const ticket = await prisma.ticket.findUnique({
    where: { id: updated.id },
    include: { requester: true, assignedTo: true }
  });

  res.json({ ticket });
});

app.post("/api/tickets/:id/comments", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });

  const schema = z.object({ body: z.string().min(1), isInternal: z.boolean().optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input" });

  const ticket = await prisma.ticket.findUnique({ where: { id: req.params.id } });
  if (!ticket) return res.status(404).json({ message: "Not found" });

  if (me.role === "EMPLOYEE" && ticket.requesterId !== me.id) return res.status(403).json({ message: "Forbidden" });

  const isInternal = (me.role !== "EMPLOYEE") ? !!parsed.data.isInternal : false;

  const comment = await prisma.ticketComment.create({
    data: { ticketId: ticket.id, authorId: me.id, body: parsed.data.body, isInternal }
  });

  // first response: first IT comment triggers
  if (me.role !== "EMPLOYEE" && !ticket.firstRespondedAt) {
    await prisma.ticket.update({ where: { id: ticket.id }, data: { firstRespondedAt: now() } });
  }

  await logAudit(me.id, "COMMENT_ADDED", { isInternal }, ticket.id);
  res.json({ comment });
});

app.post("/api/tickets/:id/reopen", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });

  const schema = z.object({ reason: z.string().min(3) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input" });

  const ticket = await prisma.ticket.findUnique({ where: { id: req.params.id } });
  if (!ticket) return res.status(404).json({ message: "Not found" });

  if (me.role === "EMPLOYEE" && ticket.requesterId !== me.id) return res.status(403).json({ message: "Forbidden" });

  // reopen allowed if resolved/closed
  if (!["RESOLVED","CLOSED"].includes(ticket.status)) {
    return res.status(409).json({ message: "Ticket is not resolved/closed" });
  }

  const updated = await prisma.ticket.update({
    where: { id: ticket.id },
    data: { status: "IN_PROGRESS", resolvedAt: null, closedAt: null }
  });

  await prisma.ticketComment.create({
    data: { ticketId: ticket.id, authorId: me.id, body: `Reopened: ${parsed.data.reason}`, isInternal: false }
  });

  await logAudit(me.id, "TICKET_REOPENED", { reason: parsed.data.reason }, ticket.id);

  res.json({ ticket: updated });
});

app.post("/api/tickets/:id/escalate", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });
  if (me.role === "EMPLOYEE") return res.status(403).json({ message: "Forbidden" });

  const schema = z.object({
    reason: z.string().min(3),
    toLevel: z.enum(["L2","L3"]),
    toTeam: z.enum(["SERVICE_DESK","NETWORK","SYSTEMS","SECURITY","APPLICATION","FIELD"])
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });

  // L1 can escalate to L2 only; L2 to L3; L3 doesn't escalate.
  if (me.role === "L1" && parsed.data.toLevel !== "L2") return res.status(403).json({ message: "L1 can only escalate to L2" });
  if (me.role === "L2" && parsed.data.toLevel !== "L3") return res.status(403).json({ message: "L2 can only escalate to L3" });
  if (me.role === "L3") return res.status(403).json({ message: "L3 cannot escalate" });

  const ticket = await prisma.ticket.findUnique({ where: { id: req.params.id } });
  if (!ticket) return res.status(404).json({ message: "Not found" });

  // find candidate in target level+team+active shift
  const candidates = await prisma.user.findMany({
    where: { active: true, role: parsed.data.toLevel, team: parsed.data.toTeam }
  });
  const activeCandidates = candidates.filter(u => isShiftActive(u.shift));
  let assignedToId = null;
  if (activeCandidates.length) {
    const counts = await Promise.all(activeCandidates.map(async (u) => {
      const openCount = await prisma.ticket.count({
        where: { assignedToId: u.id, status: { in: ["NEW","ASSIGNED","IN_PROGRESS","WAITING_ON_USER","WAITING_ON_VENDOR","ESCALATED"] } }
      });
      return { id: u.id, openCount };
    }));
    counts.sort((a,b) => a.openCount - b.openCount);
    assignedToId = counts[0].id;
  }

  const updated = await prisma.ticket.update({
    where: { id: ticket.id },
    data: {
      status: "ESCALATED",
      requiredLevel: parsed.data.toLevel,
      assignedTeam: parsed.data.toTeam,
      assignedToId,
      escalationReason: parsed.data.reason,
      escalatedAt: now(),
      escalatedById: me.id
    }
  });

  await prisma.ticketComment.create({
    data: { ticketId: ticket.id, authorId: me.id, body: `Escalated to ${parsed.data.toLevel}/${parsed.data.toTeam}: ${parsed.data.reason}`, isInternal: true }
  });

  await logAudit(me.id, "TICKET_ESCALATED", { toLevel: parsed.data.toLevel, toTeam: parsed.data.toTeam, reason: parsed.data.reason }, ticket.id);

  res.json({ ticket: updated });
});

// --- Reports (simple) ---
app.get("/api/reports/summary", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });
  if (me.role === "EMPLOYEE") return res.status(403).json({ message: "Forbidden" });

  const totalOpen = await prisma.ticket.count({ where: { status: { in: ["NEW","ASSIGNED","IN_PROGRESS","WAITING_ON_USER","WAITING_ON_VENDOR","ESCALATED"] } } });
  const byPriority = await prisma.ticket.groupBy({ by: ["priority"], _count: { priority: true } });
  const byStatus = await prisma.ticket.groupBy({ by: ["status"], _count: { status: true } });

  res.json({ totalOpen, byPriority, byStatus, currentShiftPH: currentShiftPH() });
});

app.get("/api/reports/export.csv", authRequired, async (req, res) => {
  const me = await prisma.user.findUnique({ where: { id: req.auth.sub } });
  if (!me) return res.status(401).json({ message: "Not authenticated" });
  if (me.role === "EMPLOYEE") return res.status(403).json({ message: "Forbidden" });

  const tickets = await prisma.ticket.findMany({
    orderBy: { createdAt: "desc" },
    include: { requester: true, assignedTo: true }
  });

  const header = ["humanId","subject","status","priority","category","subcategory","requester","assignedTo","createdAt","updatedAt"];
  const rows = tickets.map(t => [
    t.humanId,
    JSON.stringify(t.subject),
    t.status,
    t.priority,
    JSON.stringify(t.category),
    JSON.stringify(t.subcategory),
    JSON.stringify(t.requester?.email || ""),
    JSON.stringify(t.assignedTo?.email || ""),
    t.createdAt.toISOString(),
    t.updatedAt.toISOString()
  ].join(","));

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=tickets.csv");
  res.send([header.join(","), ...rows].join("\n"));
});

// Health check
app.get("/api/health", (req, res) => res.json({ ok: true }));

// SPA fallback: serve app.html for /app
app.get("/app", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));

// Start
app.listen(PORT, () => {
  console.log(`Alpha berthaphil running on port ${PORT} (${NODE_ENV})`);
});
