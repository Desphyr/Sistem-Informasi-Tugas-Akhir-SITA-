process.env.NODE_ENV = "test";

import { describe, it, before, after, mock } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { UserRole } from "@prisma/client";
import { createApplicationServer } from "../src/index.js";
import { authService, type SafeUser } from "../src/modules/auth/auth.service.js";
import { auditService } from "../src/modules/audit/audit.service.js";
import { prisma } from "../src/config/prisma.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAuthHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

async function fetchJson(
  url: string,
  options: RequestInit = {}
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, options);
  const body = (await res.json()) as Record<string, unknown>;
  return { status: res.status, body };
}

// ---------------------------------------------------------------------------
// Synthetic users (tidak menyentuh database — hanya token)
// ---------------------------------------------------------------------------

const adminUser: SafeUser = {
  id: "00000000-0000-0000-0000-000000000001",
  fullName: "Synthetic Admin SITA",
  email: "admin@sita.test",
  role: UserRole.ADMIN,
  createdAt: new Date("2026-01-01T00:00:00Z"),
};

const supervisorUser: SafeUser = {
  id: "00000000-0000-0000-0000-000000000002",
  fullName: "Dr. Dosen Pembimbing",
  email: "dosen@sita.test",
  role: UserRole.SUPERVISOR,
  createdAt: new Date("2026-01-01T00:00:00Z"),
};

const studentUser: SafeUser = {
  id: "00000000-0000-0000-0000-000000000003",
  fullName: "Mahasiswa Bimbingan",
  email: "mhs@sita.test",
  role: UserRole.STUDENT,
  createdAt: new Date("2026-01-01T00:00:00Z"),
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("US-03: Audit Log — Append-Only", () => {
  let testServer: Server;
  let baseUrl: string;

  let adminToken: string;
  let supervisorToken: string;
  let studentToken: string;

  before(async () => {
    adminToken = authService.generateToken(adminUser).token;
    supervisorToken = authService.generateToken(supervisorUser).token;
    studentToken = authService.generateToken(studentUser).token;

    testServer = createApplicationServer();
    await new Promise<void>((resolve) => {
      testServer.listen(0, "127.0.0.1", () => {
        const address = testServer.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      testServer.close((err) => (err ? reject(err) : resolve()));
    });
    await prisma.$disconnect();
  });

  // =========================================================================
  // A. AuditService unit tests (tidak membutuhkan DB aktif — mock prisma)
  // =========================================================================

  describe("AuditService.record()", () => {
    it("harus memanggil prisma.changeLog.create dengan field yang benar", async () => {
      const fakeLog = {
        id: "fake-id-001",
        actorId: adminUser.id,
        entityType: "user",
        entityId: adminUser.id,
        action: "LOGIN",
        changes: { field: "session", description: "Pengguna berhasil login" },
        createdAt: new Date(),
      };

      // Mock prisma.changeLog.create
      const originalCreate = prisma.changeLog.create.bind(prisma.changeLog);
      let capturedData: unknown = null;
      (prisma.changeLog as unknown as Record<string, unknown>).create = async (args: unknown) => {
        capturedData = args;
        return fakeLog;
      };

      const result = await auditService.record({
        actorId: adminUser.id,
        entityType: "user",
        entityId: adminUser.id,
        action: "LOGIN",
        changes: { field: "session", description: "Pengguna berhasil login" },
      });

      // Restore
      (prisma.changeLog as unknown as Record<string, unknown>).create = originalCreate;

      assert.ok(result, "record() harus mengembalikan objek log");
      assert.equal(result?.action, "LOGIN");
      assert.equal(result?.entityType, "user");
      assert.equal(result?.actorId, adminUser.id);
      assert.ok(capturedData !== null, "prisma.changeLog.create harus dipanggil");
    });

    it("harus mengembalikan null dan tidak melempar exception jika DB gagal", async () => {
      const originalCreate = prisma.changeLog.create.bind(prisma.changeLog);
      (prisma.changeLog as unknown as Record<string, unknown>).create = async () => {
        throw new Error("DB connection failed");
      };

      const result = await auditService.record({
        actorId: null,
        entityType: "test",
        entityId: "00000000-0000-0000-0000-000000000099",
        action: "TEST_ACTION",
      });

      (prisma.changeLog as unknown as Record<string, unknown>).create = originalCreate;

      assert.equal(result, null, "Harus mengembalikan null jika DB gagal");
    });

    it("TIDAK boleh menyertakan field sensitif (password/token) dalam changes", async () => {
      const capturedArgs: Array<unknown> = [];
      const originalCreate = prisma.changeLog.create.bind(prisma.changeLog);
      (prisma.changeLog as unknown as Record<string, unknown>).create = async (args: unknown) => {
        capturedArgs.push(args);
        return { id: "x", actorId: null, entityType: "user", entityId: "y", action: "LOGIN", changes: null, createdAt: new Date() };
      };

      await auditService.record({
        actorId: adminUser.id,
        entityType: "user",
        entityId: adminUser.id,
        action: "LOGIN",
        changes: { field: "session", description: "Login berhasil" },
      });

      (prisma.changeLog as unknown as Record<string, unknown>).create = originalCreate;

      const args = capturedArgs[0] as { data: Record<string, unknown> };
      const dataStr = JSON.stringify(args?.data ?? {}).toLowerCase();
      assert.ok(!dataStr.includes("password"), "Password TIDAK boleh ada di audit log");
      assert.ok(!dataStr.includes("passwordhash"), "passwordHash TIDAK boleh ada di audit log");
      assert.ok(!dataStr.includes("token") || dataStr.includes("tokentype") === false, "Token akses TIDAK boleh ada di audit log");
    });

    it("changes null harus tetap diterima (pencatatan tanpa payload perubahan)", async () => {
      const fakeLog = {
        id: "fake-id-002",
        actorId: null,
        entityType: "system",
        entityId: "00000000-0000-0000-0000-000000000000",
        action: "SYSTEM_START",
        changes: null,
        createdAt: new Date(),
      };

      const originalCreate = prisma.changeLog.create.bind(prisma.changeLog);
      (prisma.changeLog as unknown as Record<string, unknown>).create = async () => fakeLog;

      const result = await auditService.record({
        actorId: null,
        entityType: "system",
        entityId: "00000000-0000-0000-0000-000000000000",
        action: "SYSTEM_START",
        changes: null,
      });

      (prisma.changeLog as unknown as Record<string, unknown>).create = originalCreate;

      assert.ok(result, "Harus mengembalikan log meski changes null");
      assert.equal(result?.changes, null);
    });
  });

  // =========================================================================
  // B. AuditService tidak menyediakan update/delete
  // =========================================================================

  describe("AuditService — append-only protection", () => {
    it("AuditService tidak boleh memiliki metode update()", () => {
      assert.ok(
        !("update" in auditService),
        "AuditService TIDAK boleh memiliki metode update()"
      );
    });

    it("AuditService tidak boleh memiliki metode delete()", () => {
      assert.ok(
        !("delete" in auditService),
        "AuditService TIDAK boleh memiliki metode delete()"
      );
    });

    it("AuditService tidak boleh memiliki metode deleteMany()", () => {
      assert.ok(
        !("deleteMany" in auditService),
        "AuditService TIDAK boleh memiliki metode deleteMany()"
      );
    });
  });

  // =========================================================================
  // C. HTTP endpoint GET /api/audit/logs — RBAC enforcement
  // =========================================================================

  describe("GET /api/audit/logs — akses berdasarkan RBAC", () => {
    it("harus mengembalikan 401 jika tidak ada token", async () => {
      const { status, body } = await fetchJson(`${baseUrl}/api/audit/logs`);
      assert.equal(status, 401, "Tanpa token harus 401");
      assert.equal(body.statusCode, 401);
    });

    it("harus mengembalikan 401 jika token tidak valid", async () => {
      const { status, body } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        headers: { Authorization: "Bearer token.tidak.valid" },
      });
      assert.equal(status, 401, "Token tidak valid harus 401");
      assert.equal(body.statusCode, 401);
    });

    it("harus mengembalikan 403 jika role SUPERVISOR mencoba akses audit log", async () => {
      const { status, body } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        headers: makeAuthHeaders(supervisorToken),
      });
      assert.equal(status, 403, "SUPERVISOR tidak boleh lihat audit log");
      assert.equal(body.statusCode, 403);
    });

    it("harus mengembalikan 403 jika role STUDENT mencoba akses audit log", async () => {
      const { status, body } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        headers: makeAuthHeaders(studentToken),
      });
      assert.equal(status, 403, "STUDENT tidak boleh lihat audit log");
      assert.equal(body.statusCode, 403);
    });

    it("harus mengembalikan 200 untuk ADMIN dengan payload yang valid", async () => {
      // Mock prisma.changeLog.findMany dan count
      const originalFindMany = prisma.changeLog.findMany.bind(prisma.changeLog);
      const originalCount = prisma.changeLog.count.bind(prisma.changeLog);
      (prisma.changeLog as unknown as Record<string, unknown>).findMany = async () => [
        {
          id: "log-001",
          actorId: adminUser.id,
          entityType: "user",
          entityId: adminUser.id,
          action: "LOGIN",
          changes: { field: "session" },
          createdAt: new Date("2026-11-25T00:00:00Z"),
        },
      ];
      (prisma.changeLog as unknown as Record<string, unknown>).count = async () => 1;

      const { status, body } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        headers: makeAuthHeaders(adminToken),
      });

      (prisma.changeLog as unknown as Record<string, unknown>).findMany = originalFindMany;
      (prisma.changeLog as unknown as Record<string, unknown>).count = originalCount;

      assert.equal(status, 200, "ADMIN harus berhasil mengakses audit log");
      assert.equal(body.statusCode, 200);
      const data = body.data as Record<string, unknown>;
      assert.ok(Array.isArray(data.logs), "data.logs harus array");
      assert.ok(typeof (data.pagination as Record<string, unknown>).total === "number");
    });
  });

  // =========================================================================
  // D. HTTP — tidak ada endpoint DELETE/PATCH untuk audit log
  // =========================================================================

  describe("Audit Log — tidak ada endpoint destructive", () => {
    it("DELETE /api/audit/logs harus 404 (tidak terdaftar)", async () => {
      const { status } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        method: "DELETE",
        headers: makeAuthHeaders(adminToken),
      });
      // Server tidak mendaftarkan DELETE — harus 404
      assert.equal(status, 404, "DELETE /api/audit/logs harus 404");
    });

    it("PATCH /api/audit/logs harus 404 (tidak terdaftar)", async () => {
      const { status } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        method: "PATCH",
        headers: makeAuthHeaders(adminToken),
      });
      assert.equal(status, 404, "PATCH /api/audit/logs harus 404");
    });

    it("POST /api/audit/logs harus 404 (tidak terdaftar — log hanya via service internal)", async () => {
      const { status } = await fetchJson(`${baseUrl}/api/audit/logs`, {
        method: "POST",
        headers: makeAuthHeaders(adminToken),
        body: JSON.stringify({ action: "MANUAL_INSERT" }),
      });
      assert.equal(status, 404, "POST /api/audit/logs harus 404");
    });
  });

  // =========================================================================
  // E. Integrasi: auditService.record dipanggil saat login berhasil
  // =========================================================================

  describe("Integrasi audit log dengan proses login", () => {
    it("auditService.record dipanggil dengan actorId saat authenticateUser berhasil", async () => {
      const capturedEntries: Array<unknown> = [];
      const originalRecord = auditService.record.bind(auditService);
      auditService.record = async (entry) => {
        capturedEntries.push(entry);
        return null; // mock — tidak perlu return log nyata
      };

      // Mock DB untuk user lookup
      const originalFindUnique = prisma.user.findUnique.bind(prisma.user);
      (prisma.user as unknown as Record<string, unknown>).findUnique = async () => ({
        id: adminUser.id,
        fullName: adminUser.fullName,
        email: adminUser.email,
        role: adminUser.role,
        passwordHash: await authService.hashPassword("TestPass123!"),
        createdAt: adminUser.createdAt,
        updatedAt: new Date(),
      });

      try {
        await authService.authenticateUser(adminUser.email, "TestPass123!");
      } catch {
        // Mungkin gagal di environment tanpa DB — yang kita tes adalah apakah record dipanggil
      } finally {
        (prisma.user as unknown as Record<string, unknown>).findUnique = originalFindUnique;
        auditService.record = originalRecord;
      }

      assert.ok(capturedEntries.length >= 1, "auditService.record harus dipanggil saat login berhasil");
      const entry = capturedEntries[0] as Record<string, unknown>;
      assert.equal(entry.action, "LOGIN", "Action harus LOGIN");
      assert.equal(entry.entityType, "user", "entityType harus 'user'");
      assert.ok(!JSON.stringify(entry).toLowerCase().includes("password"), "Password TIDAK boleh ada di audit entry");
    });

    it("actorId pada audit log berasal dari identity server (bukan request body)", async () => {
      // Verifikasi bahwa auditService.record menerima actorId dari objek user terverifikasi
      // bukan dari parameter eksternal bebas
      let capturedActorId: string | null | undefined = undefined;
      const originalRecord = auditService.record.bind(auditService);
      auditService.record = async (entry) => {
        capturedActorId = entry.actorId;
        return null;
      };

      const originalFindUnique = prisma.user.findUnique.bind(prisma.user);
      (prisma.user as unknown as Record<string, unknown>).findUnique = async () => ({
        id: supervisorUser.id,
        fullName: supervisorUser.fullName,
        email: supervisorUser.email,
        role: supervisorUser.role,
        passwordHash: await authService.hashPassword("Pass456!"),
        createdAt: supervisorUser.createdAt,
        updatedAt: new Date(),
      });

      try {
        await authService.authenticateUser(supervisorUser.email, "Pass456!");
      } catch {
        // OK
      } finally {
        (prisma.user as unknown as Record<string, unknown>).findUnique = originalFindUnique;
        auditService.record = originalRecord;
      }

      assert.equal(
        capturedActorId,
        supervisorUser.id,
        "actorId harus sesuai dengan ID pengguna yang diverifikasi server"
      );
    });
  });
});
