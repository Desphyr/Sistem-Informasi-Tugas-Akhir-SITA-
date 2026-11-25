/**
 * Audit Controller — US-03
 *
 * Menyediakan endpoint baca audit log.
 * Akses dibatasi hanya untuk role ADMIN (via Permission.VIEW_AUDIT_LOG).
 * Tidak ada endpoint update atau delete — append-only.
 */

import type { ServerResponse } from "node:http";
import type { AuthenticatedRequest } from "../../middleware/auth.middleware.js";
import { requirePermission } from "../../middleware/auth.middleware.js";
import { sendJson } from "../../utils/response.js";
import { auditService } from "./audit.service.js";
import { Permission } from "../authorization/permissions.js";

export class AuditController {
  /**
   * GET /api/audit/logs
   * Mengambil daftar audit log — hanya ADMIN.
   * Query params: entityType, entityId, actorId, limit, offset
   */
  async getLogs(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const checkPermission = requirePermission(Permission.VIEW_AUDIT_LOG);
    const payload = await checkPermission(request, response);
    if (!payload) return;

    try {
      const url = new URL(request.url ?? "/", "http://localhost");
      const entityType = url.searchParams.get("entityType") ?? undefined;
      const entityId = url.searchParams.get("entityId") ?? undefined;
      const actorId = url.searchParams.get("actorId") ?? undefined;
      const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "50", 10) || 50, 200);
      const offset = Math.max(parseInt(url.searchParams.get("offset") ?? "0", 10) || 0, 0);

      const [logs, total] = await Promise.all([
        auditService.list({ entityType, entityId, actorId, limit, offset }),
        auditService.count({ entityType, entityId, actorId }),
      ]);

      sendJson(response, 200, {
        statusCode: 200,
        message: "Daftar audit log berhasil diambil.",
        data: {
          logs,
          pagination: { total, limit, offset },
        },
      });
    } catch (error: unknown) {
      console.error("[AuditController] Gagal mengambil audit log:", error);
      sendJson(response, 500, {
        statusCode: 500,
        error: "Internal Server Error",
        message: "Terjadi kesalahan saat mengambil audit log.",
      });
    }
  }
}

export const auditController = new AuditController();
