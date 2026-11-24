import type { IncomingMessage, ServerResponse } from "node:http";
import { authController } from "./auth.controller.js";

function normalizePath(url: string | undefined): string {
  if (!url) return "";
  const [pathname] = url.split("?");
  return (pathname || "").replace(/\/+$/, "");
}

export async function handleAuthRoutes(
  request: IncomingMessage,
  response: ServerResponse
): Promise<boolean> {
  const method = request.method?.toUpperCase();
  const path = normalizePath(request.url);

  // POST /auth/login or /api/auth/login
  if (method === "POST" && (path === "/auth/login" || path === "/api/auth/login")) {
    await authController.login(request, response);
    return true;
  }

  // GET /auth/me or /api/auth/me
  if (method === "GET" && (path === "/auth/me" || path === "/api/auth/me")) {
    await authController.getCurrentUser(request, response);
    return true;
  }

  // POST /auth/logout or /api/auth/logout
  if (method === "POST" && (path === "/auth/logout" || path === "/api/auth/logout")) {
    await authController.logout(request, response);
    return true;
  }

  return false;
}
