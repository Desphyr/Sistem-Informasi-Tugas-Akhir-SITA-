/**
 * Audit Routes — US-03
 *
 * Hanya mendaftarkan endpoint baca (GET).
 * Tidak ada endpoint POST/PATCH/DELETE untuk audit log dari luar.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuthenticatedRequest } from "../../middleware/auth.middleware.js";
import { auditController } from "./audit.controller.js";

function normalizePath(url: string | undefined): string {
  if (!url) return "";
  const [pathname] = url.split("?");
  return (pathname || "").replace(/\/+$/, "");
}

export async function handleAuditRoutes(
  request: IncomingMessage,
  response: ServerResponse
): Promise<boolean> {
  const method = request.method?.toUpperCase();
  const path = normalizePath(request.url);
  const authReq = request as AuthenticatedRequest;

  // GET /api/audit/logs — baca daftar audit log (ADMIN only)
  if (method === "GET" && path === "/api/audit/logs") {
    await auditController.getLogs(authReq, response);
    return true;
  }

  return false;
}
