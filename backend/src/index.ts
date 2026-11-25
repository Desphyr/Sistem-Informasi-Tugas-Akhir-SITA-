import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { config } from "./config/env.js";
import { prisma } from "./config/prisma.js";
import { handleAuthRoutes } from "./modules/auth/auth.routes.js";
import { handleAuthorizationRoutes } from "./modules/authorization/authorization.routes.js";
import { sendJson } from "./utils/response.js";

export function createApplicationServer() {
  return createServer(async (request, response) => {
    try {
      // 1. Dispatch Auth Routes (/auth/*, /api/auth/*)
      const handledByAuth = await handleAuthRoutes(request, response);
      if (handledByAuth) {
        return;
      }

      // 2. Dispatch Authorization / RBAC Routes
      const handledByRbac = await handleAuthorizationRoutes(request, response);
      if (handledByRbac) {
        return;
      }

      // 3. Health check endpoint
      if (request.method === "GET" && request.url === "/health") {
        try {
          await prisma.$queryRaw`SELECT 1`;
          sendJson(response, 200, {
            statusCode: 200,
            message: "SITA backend health check ok.",
            data: { status: "ok", database: "connected" },
          });
        } catch (error: unknown) {
          console.error("Health check database query failed:", error);
          sendJson(response, 503, {
            statusCode: 503,
            error: "Service Unavailable",
            message: "Database connection failed.",
            data: { status: "error", database: "disconnected" },
          });
        }
        return;
      }

      // 3. Fallback 404 Not Found
      sendJson(response, 404, {
        statusCode: 404,
        error: "Not Found",
        message: `Endpoint ${request.method} ${request.url} tidak ditemukan.`,
      });
    } catch (unexpectedError: unknown) {
      console.error("Unexpected server error:", unexpectedError);
      sendJson(response, 500, {
        statusCode: 500,
        error: "Internal Server Error",
        message: "Terjadi kesalahan internal pada server.",
      });
    }
  });
}

const server = createApplicationServer();

const isMainModule = Boolean(
  process.argv[1] &&
    (fileURLToPath(import.meta.url) === process.argv[1] ||
      process.argv[1].endsWith("src/index.ts") ||
      process.argv[1].endsWith("dist/src/index.js"))
);

if (isMainModule && process.env.NODE_ENV !== "test") {
  server.listen(config.port, "0.0.0.0", () => {
    console.info(`SITA backend listening on port ${config.port}.`);
  });
}

async function shutdown(): Promise<void> {
  server.close(async (error) => {
    if (error) {
      console.error("HTTP server shutdown failed:", error);
      process.exitCode = 1;
    }

    await prisma.$disconnect();
  });
}

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
