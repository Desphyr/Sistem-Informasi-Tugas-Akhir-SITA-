process.env.NODE_ENV = "test";

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import jwt from "jsonwebtoken";
import { UserRole } from "@prisma/client";
import { createApplicationServer } from "../src/index.js";
import { config } from "../src/config/env.js";
import { prisma } from "../src/config/prisma.js";
import { authorizationService } from "../src/modules/authorization/authorization.service.js";
import { Permission, ROLE_PERMISSIONS } from "../src/modules/authorization/permissions.js";
import { authService, type SafeUser } from "../src/modules/auth/auth.service.js";

describe("US-02: Role-Based Access Control (RBAC) & Data Isolation Tests", () => {
  let testServer: Server;
  let baseUrl: string;

  // Synthetic users for each role
  const adminUser: SafeUser = {
    id: "uuid-admin-001",
    fullName: "Synthetic Admin SITA",
    email: "admin@sita.example",
    role: UserRole.ADMIN,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };

  const lecturerUserA: SafeUser = {
    id: "uuid-lecturer-001",
    fullName: "Dr. Dosen Pembimbing A",
    email: "dosen.a@sita.example",
    role: UserRole.SUPERVISOR,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };

  const lecturerUserB: SafeUser = {
    id: "uuid-lecturer-002",
    fullName: "Dr. Dosen Pembimbing B",
    email: "dosen.b@sita.example",
    role: UserRole.SUPERVISOR,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };

  const studentUserA: SafeUser = {
    id: "uuid-student-001",
    fullName: "Mahasiswa Bimbingan A",
    email: "mahasiswa.a@sita.example",
    role: UserRole.STUDENT,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };

  const studentUserB: SafeUser = {
    id: "uuid-student-002",
    fullName: "Mahasiswa Bimbingan B",
    email: "mahasiswa.b@sita.example",
    role: UserRole.STUDENT,
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };

  // Pre-generate tokens
  let adminToken: string;
  let lecturerTokenA: string;
  let lecturerTokenB: string;
  let studentTokenA: string;
  let studentTokenB: string;

  before(async () => {
    adminToken = authService.generateToken(adminUser).token;
    lecturerTokenA = authService.generateToken(lecturerUserA).token;
    lecturerTokenB = authService.generateToken(lecturerUserB).token;
    studentTokenA = authService.generateToken(studentUserA).token;
    studentTokenB = authService.generateToken(studentUserB).token;

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
  });

  describe("1. Authorization Service & Role Mapping Unit Tests", () => {
    it("should correctly verify single role and multiple roles", () => {
      assert.strictEqual(authorizationService.hasRole(UserRole.ADMIN, UserRole.ADMIN), true);
      assert.strictEqual(authorizationService.hasRole(UserRole.STUDENT, UserRole.ADMIN), false);
      assert.strictEqual(
        authorizationService.hasRole(UserRole.SUPERVISOR, [UserRole.SUPERVISOR, UserRole.ADMIN]),
        true
      );
      assert.strictEqual(
        authorizationService.hasRole(UserRole.STUDENT, [UserRole.SUPERVISOR, UserRole.ADMIN]),
        false
      );
    });

    it("should correctly check permissions for each role", () => {
      // Admin has manage:users
      assert.strictEqual(authorizationService.hasPermission(UserRole.ADMIN, Permission.MANAGE_USERS), true);
      // Student cannot manage:users
      assert.strictEqual(authorizationService.hasPermission(UserRole.STUDENT, Permission.MANAGE_USERS), false);
      // Supervisor cannot manage:users
      assert.strictEqual(authorizationService.hasPermission(UserRole.SUPERVISOR, Permission.MANAGE_USERS), false);
      // Supervisor has verify:logbook
      assert.strictEqual(authorizationService.hasPermission(UserRole.SUPERVISOR, Permission.VERIFY_LOGBOOK), true);
      // Student has submit:draft
      assert.strictEqual(authorizationService.hasPermission(UserRole.STUDENT, Permission.SUBMIT_DRAFT), true);
    });

    it("should resolve proper dashboard destination per role (AC-1)", () => {
      assert.strictEqual(authorizationService.getDashboardRoute(UserRole.ADMIN), "/dashboard/admin");
      assert.strictEqual(authorizationService.getDashboardRoute(UserRole.SUPERVISOR), "/dashboard/lecturer");
      assert.strictEqual(authorizationService.getDashboardRoute(UserRole.STUDENT), "/dashboard/student");
    });
  });

  describe("2. Server-side Role-based Access Control HTTP Tests", () => {
    it("should reject requests without token with 401 Unauthorized", async () => {
      const endpoints = [
        "/api/admin/overview",
        "/api/lecturer/students",
        "/api/student/supervision",
        "/api/me/dashboard",
      ];

      for (const endpoint of endpoints) {
        const res = await fetch(`${baseUrl}${endpoint}`);
        const body = await res.json();
        assert.strictEqual(res.status, 401, `Expected 401 for ${endpoint}`);
        assert.strictEqual(body.statusCode, 401);
        assert.strictEqual(body.error, "Unauthorized");
      }
    });

    it("should reject requests with invalid token with 401", async () => {
      const res = await fetch(`${baseUrl}/api/admin/overview`, {
        headers: { Authorization: "Bearer bogus.invalid.token" },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 401);
      assert.strictEqual(body.statusCode, 401);
      assert.strictEqual(body.error, "Unauthorized");
    });

    it("should reject requests with expired token with 401", async () => {
      const expiredToken = jwt.sign(
        { sub: adminUser.id, email: adminUser.email, role: adminUser.role },
        config.jwtSecret,
        { expiresIn: "-5s" }
      );

      const res = await fetch(`${baseUrl}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${expiredToken}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 401);
      assert.strictEqual(body.statusCode, 401);
      assert.strictEqual(body.message, "Sesi login telah kedaluwarsa. Silakan login kembali.");
    });

    it("should return 403 Forbidden when Student accesses Admin endpoint", async () => {
      const res = await fetch(`${baseUrl}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${studentTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 403);
      assert.strictEqual(body.statusCode, 403);
      assert.strictEqual(body.error, "Forbidden");
      assert.strictEqual(body.message, "Akses ditolak: peran Anda tidak memiliki izin untuk mengakses resource ini.");
    });

    it("should return 403 Forbidden when Lecturer accesses Admin endpoint", async () => {
      const res = await fetch(`${baseUrl}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${lecturerTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 403);
      assert.strictEqual(body.statusCode, 403);
      assert.strictEqual(body.error, "Forbidden");
    });

    it("should return 403 Forbidden when Student accesses Lecturer endpoint", async () => {
      const res = await fetch(`${baseUrl}/api/lecturer/students`, {
        headers: { Authorization: `Bearer ${studentTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 403);
      assert.strictEqual(body.statusCode, 403);
      assert.strictEqual(body.error, "Forbidden");
    });

    it("should return 403 Forbidden when Lecturer accesses Student endpoint", async () => {
      const res = await fetch(`${baseUrl}/api/student/supervision`, {
        headers: { Authorization: `Bearer ${lecturerTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 403);
      assert.strictEqual(body.statusCode, 403);
      assert.strictEqual(body.error, "Forbidden");
    });

    it("should allow Admin to access Admin endpoint (200 OK)", async () => {
      const res = await fetch(`${baseUrl}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.statusCode, 200);
      assert.strictEqual(body.data?.scope, "ADMIN");
    });

    it("should allow Lecturer to access Lecturer endpoint (200 OK)", async () => {
      const res = await fetch(`${baseUrl}/api/lecturer/students`, {
        headers: { Authorization: `Bearer ${lecturerTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.statusCode, 200);
      assert.strictEqual(body.data?.scope, "SUPERVISOR");
      assert.strictEqual(body.data?.supervisorId, lecturerUserA.id);
    });

    it("should allow Student to access Student endpoint (200 OK)", async () => {
      const res = await fetch(`${baseUrl}/api/student/supervision`, {
        headers: { Authorization: `Bearer ${studentTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.statusCode, 200);
      assert.strictEqual(body.data?.scope, "STUDENT");
      assert.strictEqual(body.data?.studentId, studentUserA.id);
    });

    it("should ignore tampered client headers or body attempting to elevate role", async () => {
      // Student sends custom header or body pretending to be ADMIN
      const res = await fetch(`${baseUrl}/api/admin/overview`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${studentTokenA}`,
          "X-Role": "ADMIN",
          "Role": "ADMIN",
        },
      });
      assert.strictEqual(res.status, 403, "Tampered role must NOT bypass server-side check");
    });
  });

  describe("3. Dashboard Routing & Post-Authentication Target Tests (AC-1)", () => {
    it("should route Admin to /dashboard/admin", async () => {
      const res = await fetch(`${baseUrl}/api/me/dashboard`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.data?.targetDashboard, "/dashboard/admin");
      assert.strictEqual(body.data?.role, UserRole.ADMIN);
    });

    it("should route Lecturer to /dashboard/lecturer", async () => {
      const res = await fetch(`${baseUrl}/api/me/dashboard`, {
        headers: { Authorization: `Bearer ${lecturerTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.data?.targetDashboard, "/dashboard/lecturer");
      assert.strictEqual(body.data?.role, UserRole.SUPERVISOR);
    });

    it("should route Student to /dashboard/student", async () => {
      const res = await fetch(`${baseUrl}/api/me/dashboard`, {
        headers: { Authorization: `Bearer ${studentTokenA}` },
      });
      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.data?.targetDashboard, "/dashboard/student");
      assert.strictEqual(body.data?.role, UserRole.STUDENT);
    });

    it("should include targetDashboard and permissions in GET /auth/me", async () => {
      const origFindUnique = prisma.user.findUnique;
      (prisma.user as any).findUnique = async () => ({
        id: studentUserA.id,
        fullName: studentUserA.fullName,
        email: studentUserA.email,
        role: studentUserA.role,
        createdAt: studentUserA.createdAt,
      });

      try {
        const res = await fetch(`${baseUrl}/auth/me`, {
          headers: { Authorization: `Bearer ${studentTokenA}` },
        });
        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.data?.targetDashboard, "/dashboard/student");
        assert.ok(Array.isArray(body.data?.permissions));
        assert.ok(body.data?.permissions.includes(Permission.VIEW_OWN_SUPERVISION));
      } finally {
        (prisma.user as any).findUnique = origFindUnique;
      }
    });
  });

  describe("4. Academic Data Isolation Tests (NFR-01)", () => {
    const supervisionA = {
      id: "supervision-uuid-001",
      studentId: studentUserA.id,
      supervisorId: lecturerUserA.id,
      startedAt: new Date("2026-01-01T00:00:00Z"),
      student: studentUserA,
      supervisor: lecturerUserA,
    };

    it("should allow Student A to view their own supervision", async () => {
      const origFindUnique = prisma.supervision.findUnique;
      (prisma.supervision as any).findUnique = async () => supervisionA;

      try {
        const res = await fetch(`${baseUrl}/api/supervisions/${supervisionA.id}`, {
          headers: { Authorization: `Bearer ${studentTokenA}` },
        });
        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.data?.supervision?.id, supervisionA.id);
      } finally {
        (prisma.supervision as any).findUnique = origFindUnique;
      }
    });

    it("should forbid Student B from viewing Student A's supervision (403)", async () => {
      const origFindUnique = prisma.supervision.findUnique;
      (prisma.supervision as any).findUnique = async () => supervisionA;

      try {
        const res = await fetch(`${baseUrl}/api/supervisions/${supervisionA.id}`, {
          headers: { Authorization: `Bearer ${studentTokenB}` },
        });
        const body = await res.json();
        assert.strictEqual(res.status, 403);
        assert.strictEqual(body.error, "Forbidden");
        assert.strictEqual(body.message, "Akses ditolak: Anda tidak memiliki wewenang untuk melihat data bimbingan ini.");
      } finally {
        (prisma.supervision as any).findUnique = origFindUnique;
      }
    });

    it("should allow Supervisor A to view supervision of their assigned student", async () => {
      const origFindUnique = prisma.supervision.findUnique;
      (prisma.supervision as any).findUnique = async () => supervisionA;

      try {
        const res = await fetch(`${baseUrl}/api/supervisions/${supervisionA.id}`, {
          headers: { Authorization: `Bearer ${lecturerTokenA}` },
        });
        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.data?.supervision?.id, supervisionA.id);
      } finally {
        (prisma.supervision as any).findUnique = origFindUnique;
      }
    });

    it("should forbid Supervisor B from viewing supervision of Supervisor A's student (403)", async () => {
      const origFindUnique = prisma.supervision.findUnique;
      (prisma.supervision as any).findUnique = async () => supervisionA;

      try {
        const res = await fetch(`${baseUrl}/api/supervisions/${supervisionA.id}`, {
          headers: { Authorization: `Bearer ${lecturerTokenB}` },
        });
        const body = await res.json();
        assert.strictEqual(res.status, 403);
        assert.strictEqual(body.error, "Forbidden");
      } finally {
        (prisma.supervision as any).findUnique = origFindUnique;
      }
    });

    it("should allow Admin to view any supervision record", async () => {
      const origFindUnique = prisma.supervision.findUnique;
      (prisma.supervision as any).findUnique = async () => supervisionA;

      try {
        const res = await fetch(`${baseUrl}/api/supervisions/${supervisionA.id}`, {
          headers: { Authorization: `Bearer ${adminToken}` },
        });
        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.data?.supervision?.id, supervisionA.id);
      } finally {
        (prisma.supervision as any).findUnique = origFindUnique;
      }
    });
  });
});
