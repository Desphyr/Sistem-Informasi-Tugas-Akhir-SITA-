import type { ServerResponse } from "node:http";
import { UserRole } from "@prisma/client";
import { sendJson } from "../../utils/response.js";
import type { AuthenticatedRequest } from "../../middleware/auth.middleware.js";
import { requireAuth } from "../../middleware/auth.middleware.js";
import { requireRole } from "./authorization.middleware.js";
import { authorizationService } from "./authorization.service.js";
import { prisma } from "../../config/prisma.js";

export class AuthorizationController {
  /**
   * Endpoint informasi rute dashboard pasca-autentikasi sesuai role (AC-1).
   * GET /api/me/dashboard atau /auth/dashboard
   */
  async getDashboardTarget(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const payload = await requireAuth(request, response);
    if (!payload) return;

    const targetDashboard = authorizationService.getDashboardRoute(payload.role);
    const permissions = authorizationService.getRolePermissions(payload.role);

    sendJson(response, 200, {
      statusCode: 200,
      message: "Target dashboard berhasil diperoleh.",
      data: {
        userId: payload.sub,
        email: payload.email,
        role: payload.role,
        targetDashboard,
        permissions,
      },
    });
  }

  /**
   * Endpoint khusus Administrator.
   * GET /api/admin/overview
   */
  async getAdminOverview(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const checkAdmin = requireRole(UserRole.ADMIN);
    const payload = await checkAdmin(request, response);
    if (!payload) return;

    sendJson(response, 200, {
      statusCode: 200,
      message: "Akses panel admin berhasil diizinkan.",
      data: {
        scope: "ADMIN",
        accessLevel: "FULL_SYSTEM",
      },
    });
  }

  /**
   * Endpoint khusus Dosen Pembimbing (dan Admin).
   * GET /api/lecturer/students
   */
  async getLecturerPanel(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const checkLecturer = requireRole([UserRole.SUPERVISOR, UserRole.ADMIN]);
    const payload = await checkLecturer(request, response);
    if (!payload) return;

    sendJson(response, 200, {
      statusCode: 200,
      message: "Akses panel dosen pembimbing berhasil diizinkan.",
      data: {
        scope: "SUPERVISOR",
        supervisorId: payload.sub,
      },
    });
  }

  /**
   * Endpoint khusus Mahasiswa (dan Admin).
   * GET /api/student/supervision
   */
  async getStudentPanel(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const checkStudent = requireRole([UserRole.STUDENT, UserRole.ADMIN]);
    const payload = await checkStudent(request, response);
    if (!payload) return;

    sendJson(response, 200, {
      statusCode: 200,
      message: "Akses panel mahasiswa berhasil diizinkan.",
      data: {
        scope: "STUDENT",
        studentId: payload.sub,
      },
    });
  }

  /**
   * Endpoint pemeriksaan data bimbingan dengan isolasi akses (NFR-01).
   * GET /api/supervisions/:id
   */
  async getSupervisionById(
    request: AuthenticatedRequest,
    response: ServerResponse,
    supervisionId: string
  ): Promise<void> {
    const payload = await requireAuth(request, response);
    if (!payload) return;

    const canAccess = await authorizationService.canAccessSupervision(payload, supervisionId);
    if (!canAccess) {
      sendJson(response, 403, {
        statusCode: 403,
        error: "Forbidden",
        message: "Akses ditolak: Anda tidak memiliki wewenang untuk melihat data bimbingan ini.",
      });
      return;
    }

    const supervision = await prisma.supervision.findUnique({
      where: { id: supervisionId },
      include: {
        student: { select: { id: true, fullName: true, email: true, role: true } },
        supervisor: { select: { id: true, fullName: true, email: true, role: true } },
      },
    });

    if (!supervision) {
      sendJson(response, 404, {
        statusCode: 404,
        error: "Not Found",
        message: "Data bimbingan tidak ditemukan.",
      });
      return;
    }

    sendJson(response, 200, {
      statusCode: 200,
      message: "Data bimbingan berhasil diambil.",
      data: { supervision },
    });
  }
}

export const authorizationController = new AuthorizationController();
