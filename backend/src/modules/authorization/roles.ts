import { UserRole } from "@prisma/client";

export const ROLES = {
  ADMIN: UserRole.ADMIN,
  SUPERVISOR: UserRole.SUPERVISOR, // Dosen Pembimbing
  STUDENT: UserRole.STUDENT,       // Mahasiswa Bimbingan
} as const;

export type AppRole = UserRole;

export const ROLE_LABELS: Record<UserRole, string> = {
  [UserRole.ADMIN]: "Administrator Sistem",
  [UserRole.SUPERVISOR]: "Dosen Pembimbing",
  [UserRole.STUDENT]: "Mahasiswa",
};

export const ROLE_DASHBOARD_ROUTES: Record<UserRole, string> = {
  [UserRole.ADMIN]: "/dashboard/admin",
  [UserRole.SUPERVISOR]: "/dashboard/lecturer",
  [UserRole.STUDENT]: "/dashboard/student",
};
