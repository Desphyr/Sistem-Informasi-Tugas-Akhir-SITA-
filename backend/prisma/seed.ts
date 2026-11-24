import { PrismaClient, UserRole } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

const DEFAULT_DEV_PASSWORD = "Password123!";

const rawUsers = [
  { fullName: "Admin SITA", email: "admin@sita.example", role: UserRole.ADMIN },
  { fullName: "Dosen Satu", email: "dosen1@sita.example", role: UserRole.SUPERVISOR },
  { fullName: "Dosen Dua", email: "dosen2@sita.example", role: UserRole.SUPERVISOR },
  { fullName: "Dosen Tiga", email: "dosen3@sita.example", role: UserRole.SUPERVISOR },
  { fullName: "Mahasiswa Satu", email: "mahasiswa1@sita.example", role: UserRole.STUDENT },
  { fullName: "Mahasiswa Dua", email: "mahasiswa2@sita.example", role: UserRole.STUDENT },
  { fullName: "Mahasiswa Tiga", email: "mahasiswa3@sita.example", role: UserRole.STUDENT },
  { fullName: "Mahasiswa Empat", email: "mahasiswa4@sita.example", role: UserRole.STUDENT },
  { fullName: "Mahasiswa Lima", email: "mahasiswa5@sita.example", role: UserRole.STUDENT },
];

const supervisionAssignments = [
  { studentEmail: "mahasiswa1@sita.example", supervisorEmail: "dosen1@sita.example" },
  { studentEmail: "mahasiswa2@sita.example", supervisorEmail: "dosen1@sita.example" },
  { studentEmail: "mahasiswa3@sita.example", supervisorEmail: "dosen2@sita.example" },
  { studentEmail: "mahasiswa4@sita.example", supervisorEmail: "dosen2@sita.example" },
  { studentEmail: "mahasiswa5@sita.example", supervisorEmail: "dosen3@sita.example" },
];

async function main(): Promise<void> {
  const usersByEmail = new Map<string, string>();
  const defaultPasswordHash = await bcrypt.hash(DEFAULT_DEV_PASSWORD, 10);

  for (const user of rawUsers) {
    const savedUser = await prisma.user.upsert({
      where: { email: user.email },
      update: {
        fullName: user.fullName,
        role: user.role,
        passwordHash: defaultPasswordHash,
      },
      create: {
        ...user,
        passwordHash: defaultPasswordHash,
      },
    });
    usersByEmail.set(savedUser.email, savedUser.id);
  }

  for (const assignment of supervisionAssignments) {
    const studentId = usersByEmail.get(assignment.studentEmail);
    const supervisorId = usersByEmail.get(assignment.supervisorEmail);

    if (!studentId || !supervisorId) {
      throw new Error(`Missing seeded user for ${assignment.studentEmail}`);
    }

    await prisma.supervision.upsert({
      where: { studentId },
      update: { supervisorId },
      create: { studentId, supervisorId },
    });
  }

  console.info("Seeded 1 admin, 3 supervisors, 5 students, and 5 supervision assignments with secure hashed passwords.");
}

main()
  .catch((error: unknown) => {
    console.error("Database seed failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
