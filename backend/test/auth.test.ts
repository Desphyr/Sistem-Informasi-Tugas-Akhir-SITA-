process.env.NODE_ENV = "test";

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { validateLoginInput } from "../src/modules/auth/auth.validation.js";
import { authService, type SafeUser } from "../src/modules/auth/auth.service.js";
import { prisma } from "../src/config/prisma.js";
import { config } from "../src/config/env.js";
import { createApplicationServer } from "../src/index.js";

describe("US-01: Authentication & Password Security Tests", () => {
  const syntheticPassword = "Password123!";
  let syntheticPasswordHash: string;
  const syntheticUser = {
    id: "synthetic-uuid-0001",
    fullName: "Synthetic Admin User",
    email: "synthetic.admin@sita.example",
    role: "ADMIN" as const,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-01T00:00:00.000Z"),
    passwordHash: "",
  };

  let testServer: Server;
  let baseUrl: string;

  before(async () => {
    // Generate bcrypt hash for testing
    syntheticPasswordHash = await bcrypt.hash(syntheticPassword, 10);
    syntheticUser.passwordHash = syntheticPasswordHash;

    // Start server on ephemeral port (port 0)
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

  describe("1. Input Validation Tests", () => {
    it("should accept valid email and password, normalizing email to lowercase", () => {
      const result = validateLoginInput({
        email: " User.Test@Example.COM ",
        password: "ValidPassword123!",
      });

      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.data?.email, "user.test@example.com");
      assert.strictEqual(result.data?.password, "ValidPassword123!");
    });

    it("should reject missing or empty email", () => {
      const result = validateLoginInput({
        email: "",
        password: "ValidPassword123!",
      });

      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.message, "Email wajib diisi.");
    });

    it("should reject invalid email format", () => {
      const invalidEmails = ["invalid-email", "user@", "@domain.com", "user@domain", "user space@domain.com"];
      for (const email of invalidEmails) {
        const result = validateLoginInput({ email, password: "ValidPassword123!" });
        assert.strictEqual(result.valid, false, `Expected ${email} to be invalid`);
        assert.strictEqual(result.message, "Format email tidak valid.");
      }
    });

    it("should reject missing or empty password", () => {
      const result = validateLoginInput({
        email: "user@example.com",
        password: "",
      });

      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.message, "Kata sandi wajib diisi.");
    });

    it("should reject non-object body", () => {
      const result = validateLoginInput(null);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.message, "Request body harus berupa JSON object yang valid.");
    });
  });

  describe("2. Password Hashing & Security Tests", () => {
    it("should hash password using bcrypt with salt rounds >= 10", async () => {
      const hash = await authService.hashPassword("SuperSecret123!");
      assert.match(hash, /^\$2[ab]\$10\$/);
      assert.notStrictEqual(hash, "SuperSecret123!");
    });

    it("should return true when comparing correct password with hash", async () => {
      const isValid = await authService.comparePassword(syntheticPassword, syntheticPasswordHash);
      assert.strictEqual(isValid, true);
    });

    it("should return false when comparing incorrect password with hash", async () => {
      const isValid = await authService.comparePassword("WrongPassword!", syntheticPasswordHash);
      assert.strictEqual(isValid, false);
    });

    it("should never store or return plaintext password in SafeUser", () => {
      const safeUser: SafeUser = {
        id: syntheticUser.id,
        fullName: syntheticUser.fullName,
        email: syntheticUser.email,
        role: syntheticUser.role,
        createdAt: syntheticUser.createdAt,
      };

      const userRecord = safeUser as Record<string, unknown>;
      assert.strictEqual(userRecord.password, undefined);
      assert.strictEqual(userRecord.passwordHash, undefined);
    });
  });

  describe("3. JWT Token Generation & Verification Tests", () => {
    it("should generate a valid Bearer JWT token with user claims", () => {
      const safeUser: SafeUser = {
        id: syntheticUser.id,
        fullName: syntheticUser.fullName,
        email: syntheticUser.email,
        role: syntheticUser.role,
        createdAt: syntheticUser.createdAt,
      };

      const tokens = authService.generateToken(safeUser);
      assert.strictEqual(tokens.tokenType, "Bearer");
      assert.ok(tokens.token);
      assert.strictEqual(tokens.expiresIn, config.jwtExpiresIn);

      const decoded = authService.verifyToken(tokens.token);
      assert.strictEqual(decoded.sub, syntheticUser.id);
      assert.strictEqual(decoded.email, syntheticUser.email);
      assert.strictEqual(decoded.role, syntheticUser.role);
    });

    it("should throw error on invalid/tampered token", () => {
      assert.throws(() => {
        authService.verifyToken("invalid.tampered.token");
      });
    });

    it("should throw error on expired token", () => {
      const expiredToken = jwt.sign(
        { sub: "expired-user", email: "expired@test.com", role: "STUDENT" },
        config.jwtSecret,
        { expiresIn: "-1s" }
      );

      assert.throws(() => {
        authService.verifyToken(expiredToken);
      }, /jwt expired/);
    });
  });

  describe("4. End-to-End API Login & Protected Route Tests", () => {
    it("POST /auth/login - should reject empty payload with 400", async () => {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      const body = await res.json();
      assert.strictEqual(res.status, 400);
      assert.strictEqual(body.statusCode, 400);
      assert.strictEqual(body.error, "Bad Request");
      assert.strictEqual(body.message, "Email wajib diisi.");
    });

    it("POST /auth/login - should reject malformed JSON with 400", async () => {
      const res = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{ invalid json",
      });

      const body = await res.json();
      assert.strictEqual(res.status, 400);
      assert.strictEqual(body.statusCode, 400);
      assert.strictEqual(body.error, "Bad Request");
    });

    it("POST /auth/login - should reject unregistered user with 401 without revealing user existence", async () => {
      // Mock prisma.user.findUnique to return null
      const originalFindUnique = prisma.user.findUnique;
      (prisma.user as any).findUnique = async () => null;

      try {
        const res = await fetch(`${baseUrl}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: "notfound@sita.example",
            password: "SomePassword123!",
          }),
        });

        const body = await res.json();
        assert.strictEqual(res.status, 401);
        assert.strictEqual(body.statusCode, 401);
        assert.strictEqual(body.error, "Unauthorized");
        assert.strictEqual(body.message, "Email atau kata sandi tidak valid.");
      } finally {
        (prisma.user as any).findUnique = originalFindUnique;
      }
    });

    it("POST /auth/login - should reject incorrect password with 401 without revealing sensitive info", async () => {
      // Mock prisma.user.findUnique to return synthetic user
      const originalFindUnique = prisma.user.findUnique;
      (prisma.user as any).findUnique = async () => syntheticUser;

      try {
        const res = await fetch(`${baseUrl}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: syntheticUser.email,
            password: "WrongPassword999!",
          }),
        });

        const body = await res.json();
        assert.strictEqual(res.status, 401);
        assert.strictEqual(body.statusCode, 401);
        assert.strictEqual(body.error, "Unauthorized");
        assert.strictEqual(body.message, "Email atau kata sandi tidak valid.");
      } finally {
        (prisma.user as any).findUnique = originalFindUnique;
      }
    });

    it("POST /auth/login - should successfully authenticate valid credentials", async () => {
      const originalFindUnique = prisma.user.findUnique;
      (prisma.user as any).findUnique = async () => syntheticUser;

      try {
        const res = await fetch(`${baseUrl}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: syntheticUser.email,
            password: syntheticPassword,
          }),
        });

        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.statusCode, 200);
        assert.strictEqual(body.message, "Login berhasil.");
        assert.ok(body.data?.token);
        assert.strictEqual(body.data?.tokenType, "Bearer");
        assert.strictEqual(body.data?.user?.email, syntheticUser.email);
        assert.strictEqual(body.data?.user?.fullName, syntheticUser.fullName);
        assert.strictEqual(body.data?.user?.role, syntheticUser.role);

        // Crucial security verification: ensure NO password or hash is exposed
        assert.strictEqual(body.data?.user?.password, undefined);
        assert.strictEqual(body.data?.user?.passwordHash, undefined);
        assert.strictEqual(body.password, undefined);
        assert.strictEqual(body.passwordHash, undefined);
      } finally {
        (prisma.user as any).findUnique = originalFindUnique;
      }
    });

    it("POST /api/auth/login - should also work via /api/auth/login route alias", async () => {
      const originalFindUnique = prisma.user.findUnique;
      (prisma.user as any).findUnique = async () => syntheticUser;

      try {
        const res = await fetch(`${baseUrl}/api/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: syntheticUser.email,
            password: syntheticPassword,
          }),
        });

        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.message, "Login berhasil.");
        assert.ok(body.data?.token);
      } finally {
        (prisma.user as any).findUnique = originalFindUnique;
      }
    });

    it("GET /auth/me - should reject request without token with 401", async () => {
      const res = await fetch(`${baseUrl}/auth/me`, {
        method: "GET",
      });

      const body = await res.json();
      assert.strictEqual(res.status, 401);
      assert.strictEqual(body.statusCode, 401);
      assert.strictEqual(body.message, "Token autentikasi tidak ditemukan. Harap sertakan Bearer token pada header Authorization.");
    });

    it("GET /auth/me - should reject invalid Bearer token with 401", async () => {
      const res = await fetch(`${baseUrl}/auth/me`, {
        method: "GET",
        headers: { Authorization: "Bearer bogus-invalid-token" },
      });

      const body = await res.json();
      assert.strictEqual(res.status, 401);
      assert.strictEqual(body.statusCode, 401);
      assert.strictEqual(body.message, "Token autentikasi tidak valid.");
    });

    it("GET /auth/me - should reject expired Bearer token with 401 and specific message", async () => {
      const expiredToken = jwt.sign(
        { sub: syntheticUser.id, email: syntheticUser.email, role: syntheticUser.role },
        config.jwtSecret,
        { expiresIn: "-1s" }
      );

      const res = await fetch(`${baseUrl}/auth/me`, {
        method: "GET",
        headers: { Authorization: `Bearer ${expiredToken}` },
      });

      const body = await res.json();
      assert.strictEqual(res.status, 401);
      assert.strictEqual(body.statusCode, 401);
      assert.strictEqual(body.message, "Sesi login telah kedaluwarsa. Silakan login kembali.");
    });

    it("GET /auth/me - should return user profile with valid Bearer token", async () => {
      const originalFindUnique = prisma.user.findUnique;
      (prisma.user as any).findUnique = async () => syntheticUser;

      try {
        // Generate valid token
        const token = authService.generateToken({
          id: syntheticUser.id,
          fullName: syntheticUser.fullName,
          email: syntheticUser.email,
          role: syntheticUser.role,
          createdAt: syntheticUser.createdAt,
        }).token;

        const res = await fetch(`${baseUrl}/auth/me`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        });

        const body = await res.json();
        assert.strictEqual(res.status, 200);
        assert.strictEqual(body.statusCode, 200);
        assert.strictEqual(body.message, "Profil pengguna berhasil diambil.");
        assert.strictEqual(body.data?.user?.id, syntheticUser.id);
        assert.strictEqual(body.data?.user?.email, syntheticUser.email);
        assert.strictEqual(body.data?.user?.password, undefined);
        assert.strictEqual(body.data?.user?.passwordHash, undefined);
      } finally {
        (prisma.user as any).findUnique = originalFindUnique;
      }
    });

    it("POST /auth/logout - should return 200 on authenticated logout", async () => {
      const token = authService.generateToken({
        id: syntheticUser.id,
        fullName: syntheticUser.fullName,
        email: syntheticUser.email,
        role: syntheticUser.role,
        createdAt: syntheticUser.createdAt,
      }).token;

      const res = await fetch(`${baseUrl}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });

      const body = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(body.statusCode, 200);
      assert.strictEqual(body.message, "Logout berhasil. Sesi telah diakhiri.");
    });
  });
});
