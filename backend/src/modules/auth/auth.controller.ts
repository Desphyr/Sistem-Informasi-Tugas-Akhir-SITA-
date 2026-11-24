import type { IncomingMessage, ServerResponse } from "node:http";
import { parseJsonBody, sendJson } from "../../utils/response.js";
import { validateLoginInput } from "./auth.validation.js";
import { authService } from "./auth.service.js";
import { requireAuth, type AuthenticatedRequest } from "../../middleware/auth.middleware.js";

export class AuthController {
  async login(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      const body = await parseJsonBody(request);
      const validation = validateLoginInput(body);

      if (!validation.valid || !validation.data) {
        sendJson(response, 400, {
          statusCode: 400,
          error: "Bad Request",
          message: validation.message,
        });
        return;
      }

      const { email, password } = validation.data;

      try {
        const result = await authService.authenticateUser(email, password);

        sendJson(response, 200, {
          statusCode: 200,
          message: "Login berhasil.",
          data: {
            token: result.tokens.token,
            tokenType: result.tokens.tokenType,
            expiresIn: result.tokens.expiresIn,
            user: result.user,
          },
        });
      } catch (authError: unknown) {
        const errorMessage = authError instanceof Error ? authError.message : "Autentikasi gagal.";
        sendJson(response, 401, {
          statusCode: 401,
          error: "Unauthorized",
          message: errorMessage,
        });
      }
    } catch (parseError: unknown) {
      sendJson(response, 400, {
        statusCode: 400,
        error: "Bad Request",
        message: parseError instanceof Error ? parseError.message : "Request body tidak valid.",
      });
    }
  }

  async getCurrentUser(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const payload = await requireAuth(request, response);
    if (!payload) {
      return;
    }

    try {
      const user = await authService.getUserById(payload.sub);
      if (!user) {
        sendJson(response, 404, {
          statusCode: 404,
          error: "Not Found",
          message: "Pengguna tidak ditemukan.",
        });
        return;
      }

      sendJson(response, 200, {
        statusCode: 200,
        message: "Profil pengguna berhasil diambil.",
        data: {
          user,
        },
      });
    } catch (error: unknown) {
      console.error("Gagal mengambil profil pengguna:", error);
      sendJson(response, 500, {
        statusCode: 500,
        error: "Internal Server Error",
        message: "Terjadi kesalahan pada server saat memproses data pengguna.",
      });
    }
  }

  async logout(request: AuthenticatedRequest, response: ServerResponse): Promise<void> {
    const payload = await requireAuth(request, response);
    if (!payload) {
      return;
    }

    sendJson(response, 200, {
      statusCode: 200,
      message: "Logout berhasil. Sesi telah diakhiri.",
    });
  }
}

export const authController = new AuthController();
