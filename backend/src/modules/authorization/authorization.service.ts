import { UserRole } from "@prisma/client";
import { prisma } from "../../config/prisma.js";
import type { TokenPayload } from "../auth/auth.service.js";
import { ROLE_DASHBOARD_ROUTES } from "./roles.js";
import { Permission, ROLE_PERMISSIONS } from "./permissions.js";

export class AuthorizationService {
  /**
   * Memeriksa apakah role pengguna termasuk dalam daftar role yang diizinkan.
   */
  hasRole(userRole: UserRole, allowedRoles: UserRole | UserRole[]): boolean {
    const rolesArray = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
    return rolesArray.includes(userRole);
  }

  /**
   * Memeriksa apakah role pengguna memiliki hak akses (permission) tertentu.
   */
  hasPermission(userRole: UserRole, requiredPermission: Permission): boolean {
    const permissions = ROLE_PERMISSIONS[userRole] ?? [];
    return permissions.includes(requiredPermission);
  }

  /**
   * Memeriksa apakah role pengguna memiliki semua hak akses yang diminta.
   */
  hasAllPermissions(userRole: UserRole, requiredPermissions: Permission[]): boolean {
    const permissions = ROLE_PERMISSIONS[userRole] ?? [];
    return requiredPermissions.every((p) => permissions.includes(p));
  }

  /**
   * Mendapatkan daftar seluruh hak akses untuk role tertentu.
   */
  getRolePermissions(userRole: UserRole): readonly Permission[] {
    return ROLE_PERMISSIONS[userRole] ?? [];
  }

  /**
   * Mendapatkan URL target dashboard sesuai role pasca-autentikasi (AC-1).
   */
  getDashboardRoute(userRole: UserRole): string {
    return ROLE_DASHBOARD_ROUTES[userRole] ?? "/dashboard";
  }

  /**
   * Validasi isolasi data bimbingan (NFR-01):
   * - Admin: Dapat mengakses semua bimbingan.
   * - Dosen (SUPERVISOR): Hanya dapat mengakses bimbingan mahasiswa yang dibimbingnya secara resmi.
   * - Mahasiswa (STUDENT): Hanya dapat melihat data bimbingannya sendiri.
   */
  async canAccessSupervision(actor: TokenPayload, supervisionId: string): Promise<boolean> {
    if (actor.role === UserRole.ADMIN) {
      return true;
    }

    const supervision = await prisma.supervision.findUnique({
      where: { id: supervisionId },
      select: { studentId: true, supervisorId: true },
    });

    if (!supervision) {
      return false;
    }

    if (actor.role === UserRole.STUDENT) {
      return supervision.studentId === actor.sub;
    }

    if (actor.role === UserRole.SUPERVISOR) {
      return supervision.supervisorId === actor.sub;
    }

    return false;
  }

  /**
   * Validasi akses data mahasiswa (NFR-01):
   * - Mahasiswa hanya dapat mengakses datanya sendiri.
   * - Dosen hanya dapat mengakses mahasiswa yang dibimbingnya.
   * - Admin dapat mengakses seluruh mahasiswa.
   */
  async canAccessStudentData(actor: TokenPayload, studentId: string): Promise<boolean> {
    if (actor.role === UserRole.ADMIN) {
      return true;
    }

    if (actor.role === UserRole.STUDENT) {
      return actor.sub === studentId;
    }

    if (actor.role === UserRole.SUPERVISOR) {
      const supervision = await prisma.supervision.findFirst({
        where: {
          supervisorId: actor.sub,
          studentId,
        },
      });
      return Boolean(supervision);
    }

    return false;
  }
}

export const authorizationService = new AuthorizationService();
