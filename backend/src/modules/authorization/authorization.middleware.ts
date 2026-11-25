import type { ServerResponse } from "node:http";
import { UserRole } from "@prisma/client";
import { requireAuth, type AuthenticatedRequest } from "../../middleware/auth.middleware.js";
import type { TokenPayload } from "../auth/auth.service.js";
import { sendJson } from "../../utils/response.js";
import { authorizationService } from "./authorization.service.js";
import type { Permission } from "./permissions.js";

/**
 * Middleware untuk membatasi akses endpoint berdasarkan satu atau beberapa UserRole.
 * - Mengembalikan 401 jika pengguna belum terautentikasi / token tidak valid.
 * - Mengembalikan 403 jika role pengguna tidak diizinkan.
 */
export function requireRole(allowedRoles: UserRole | UserRole[]) {
  return async (
    request: AuthenticatedRequest,
    response: ServerResponse
  ): Promise<TokenPayload | null> => {
    // 1. Verifikasi autentikasi token
    const payload = await requireAuth(request, response);
    if (!payload) {
      return null;
    }

    // 2. Verifikasi kesesuaian role
    const isAllowed = authorizationService.hasRole(payload.role, allowedRoles);
    if (!isAllowed) {
      sendJson(response, 403, {
        statusCode: 403,
        error: "Forbidden",
        message: "Akses ditolak: peran Anda tidak memiliki izin untuk mengakses resource ini.",
      });
      return null;
    }

    return payload;
  };
}

/**
 * Middleware untuk membatasi akses endpoint berdasarkan satu atau beberapa Permission.
 * - Mengembalikan 401 jika pengguna belum terautentikasi.
 * - Mengembalikan 403 jika permission role pengguna tidak mencukupi.
 */
export function requirePermission(permissions: Permission | Permission[]) {
  return async (
    request: AuthenticatedRequest,
    response: ServerResponse
  ): Promise<TokenPayload | null> => {
    const payload = await requireAuth(request, response);
    if (!payload) {
      return null;
    }

    const permsArray = Array.isArray(permissions) ? permissions : [permissions];
    const isAllowed = authorizationService.hasAllPermissions(payload.role, permsArray);
    if (!isAllowed) {
      sendJson(response, 403, {
        statusCode: 403,
        error: "Forbidden",
        message: "Akses ditolak: hak akses (permission) tidak mencukupi untuk tindakan ini.",
      });
      return null;
    }

    return payload;
  };
}
