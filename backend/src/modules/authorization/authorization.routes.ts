import type { IncomingMessage, ServerResponse } from "node:http";
import { authorizationController } from "./authorization.controller.js";
import type { AuthenticatedRequest } from "../../middleware/auth.middleware.js";

function normalizePath(url: string | undefined): string {
  if (!url) return "";
  const [pathname] = url.split("?");
  return (pathname || "").replace(/\/+$/, "");
}

export async function handleAuthorizationRoutes(
  request: IncomingMessage,
  response: ServerResponse
): Promise<boolean> {
  const method = request.method?.toUpperCase();
  const path = normalizePath(request.url);
  const authReq = request as AuthenticatedRequest;

  // 1. Dashboard target route: GET /api/me/dashboard or /auth/dashboard
  if (method === "GET" && (path === "/api/me/dashboard" || path === "/auth/dashboard")) {
    await authorizationController.getDashboardTarget(authReq, response);
    return true;
  }

  // 2. Admin protected route: GET /api/admin/overview or /api/admin/dashboard
  if (method === "GET" && (path === "/api/admin/overview" || path === "/api/admin/dashboard")) {
    await authorizationController.getAdminOverview(authReq, response);
    return true;
  }

  // 3. Lecturer / Supervisor protected route: GET /api/lecturer/students or /api/supervisor/dashboard
  if (
    method === "GET" &&
    (path === "/api/lecturer/students" || path === "/api/supervisor/dashboard")
  ) {
    await authorizationController.getLecturerPanel(authReq, response);
    return true;
  }

  // 4. Student protected route: GET /api/student/supervision or /api/student/dashboard
  if (
    method === "GET" &&
    (path === "/api/student/supervision" || path === "/api/student/dashboard")
  ) {
    await authorizationController.getStudentPanel(authReq, response);
    return true;
  }

  // 5. Data isolation route: GET /api/supervisions/:id
  const supervisionMatch = path.match(/^\/api\/supervisions\/([a-zA-Z0-9_-]+)$/);
  if (method === "GET" && supervisionMatch) {
    const supervisionId = supervisionMatch[1] as string;
    await authorizationController.getSupervisionById(authReq, response, supervisionId);
    return true;
  }

  return false;
}
