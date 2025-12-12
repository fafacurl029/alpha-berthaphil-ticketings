/**
 * Seed: creates a TicketCounter row and an initial demo employee.
 * Admin is created via /setup.html with BOOTSTRAP_TOKEN (one-time).
 */
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");

const prisma = new PrismaClient();

async function main() {
  // TicketCounter (id=1)
  const counter = await prisma.ticketCounter.findUnique({ where: { id: 1 } });
  if (!counter) {
    await prisma.ticketCounter.create({ data: { id: 1, nextNo: 0 } });
    console.log("Created TicketCounter(id=1, nextNo=1)");
  }

  // Demo employee
  const demoEmail = "employee@alpha.local";
  const exists = await prisma.user.findUnique({ where: { email: demoEmail } });
  if (!exists) {
    const passwordHash = await bcrypt.hash("Employee123!", 10);
    await prisma.user.create({
      data: {
        name: "Demo Employee",
        email: demoEmail,
        passwordHash,
        role: "EMPLOYEE",
        team: "SERVICE_DESK",
        shift: "MORNING",
        active: true
      }
    });
    console.log("Created demo employee: employee@alpha.local / Employee123!");
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
