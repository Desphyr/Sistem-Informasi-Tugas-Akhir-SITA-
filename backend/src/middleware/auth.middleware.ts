import type { IncomingMessage, ServerResponse } from "node:http";
import { authService, type TokenPayload } from "../modules/auth/auth.service.js";
import { sendJson } from "../utils/response.js";

export interface AuthenticatedRequest extends IncomingMessage {
  user?: TokenPayload;
}

export function extractBearerToken(request: IncomingMessage): string | null {
  const authHeader = request.headers.authorization;
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0]?.toLowerCase() !== "bearer") {
    return null;
  }

  return parts[1] || null;
}

export async function requireAuth(
  request: AuthenticatedRequest,
  response: ServerResponse
): Promise<TokenPayload | null> {
  const token = extractBearerToken(request);

  if (!token) {
    sendJson(response, 401, {
      statusCode: 401,
      error: "Unauthorized",
      message: "Token autentikasi tidak ditemukan. Harap sertakan Bearer token pada header Authorization.",
    });
    return null;
  }

  try {
    const payload = authService.verifyToken(token);
    request.user = payload;
    return payload;
  } catch (error: unknown) {
    const message =
      error instanceof Error && error.name === "TokenExpiredError"
        ? "Sesi login telah kedaluwarsa. Silakan login kembali."
        : "Token autentikasi tidak valid.";

    sendJson(response, 401, {
      statusCode: 401,
      error: "Unauthorized",
      message,
    });
    return null;
  }
}

export { requireRole, requirePermission } from "../modules/authorization/authorization.middleware.js";

