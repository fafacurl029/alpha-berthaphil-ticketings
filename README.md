# Alpha berthaphil — Internal IT Ticketing System

Shared, web-based ticketing system for an internal BPO IT operation: **L1 / L2 / L3**, **teams** (Network, Systems, etc.), **shift-aware auto-assignment**, **SLA tracking**, comments, and audit logs.

## Tech
- Node.js + Express
- PostgreSQL (Render)
- Prisma ORM
- Vanilla HTML/CSS/JS frontend (served by backend)

## Quick Deploy (Render + GitHub)

### 1) Create Render PostgreSQL
Create a new **PostgreSQL** service in Render and copy the **Internal Database URL**.

### 2) Create Render Web Service
Connect this GitHub repo.

**Build command**
```bash
npm install && npx prisma generate && npx prisma db push && node prisma/seed.js
```

**Start command**
```bash
npm start
```

### 3) Add Environment Variables (Render → Web Service → Environment)
- `DATABASE_URL` = Render Postgres Internal URL
- `JWT_SECRET` = long random string
- `BOOTSTRAP_TOKEN` = long random string
- `NODE_ENV` = `production`

### 4) Bootstrap first Admin (one-time)
Open:
- `/setup.html`

Enter `BOOTSTRAP_TOKEN`, then create your first Admin account.

### 5) Login
- `/login.html`

## Local dev
```bash
cp .env.example .env
npm install
npx prisma generate
npx prisma db push
node prisma/seed.js
npm run dev
```

Open:
- http://localhost:3000/setup.html
- http://localhost:3000/login.html
