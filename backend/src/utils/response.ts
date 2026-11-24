import type { IncomingMessage, ServerResponse } from "node:http";

export interface ApiResponse<T = unknown> {
  statusCode: number;
  message?: string;
  error?: string;
  data?: T;
}

export function sendJson<T>(
  response: ServerResponse,
  statusCode: number,
  payload: ApiResponse<T>
): void {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(payload));
}

export async function parseJsonBody<T = Record<string, unknown>>(
  request: IncomingMessage
): Promise<T> {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf-8");
      // Prevent payload too large (max 1MB)
      if (body.length > 1e6) {
        request.destroy();
        reject(new Error("Payload too large"));
      }
    });

    request.on("end", () => {
      if (!body.trim()) {
        resolve({} as T);
        return;
      }
      try {
        const parsed = JSON.parse(body) as T;
        resolve(parsed);
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });

    request.on("error", (err) => {
      reject(err);
    });
  });
}
