import { createServer } from "node:http";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const port = Number(process.env.PORT ?? 3000);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

const server = createServer(async (request, response) => {
  if (request.method !== "GET" || request.url !== "/health") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "Not Found" }));
    return;
  }

  try {
    await prisma.$queryRaw`SELECT 1`;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok", database: "connected" }));
  } catch (error: unknown) {
    console.error("Health check database query failed:", error);
    response.writeHead(503, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "error", database: "disconnected" }));
  }
});

server.listen(port, "0.0.0.0", () => {
  console.info(`SITA backend listening on port ${port}.`);
});

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
