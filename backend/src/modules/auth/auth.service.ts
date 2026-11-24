import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import type { UserRole } from "@prisma/client";
import { prisma } from "../../config/prisma.js";
import { config } from "../../config/env.js";

export interface SafeUser {
  id: string;
  fullName: string;
  email: string;
  role: UserRole;
  createdAt: Date;
}

export interface AuthTokens {
  token: string;
  tokenType: string;
  expiresIn: string;
}

export interface LoginResult {
  user: SafeUser;
  tokens: AuthTokens;
}

export interface TokenPayload {
  sub: string;
  email: string;
  role: UserRole;
  iat?: number;
  exp?: number;
}

// Dummy hash to defend against timing attacks when user is not found
const DUMMY_HASH = "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12";

export class AuthService {
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  generateToken(user: SafeUser): AuthTokens {
    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, config.jwtSecret, {
      expiresIn: config.jwtExpiresIn,
    } as jwt.SignOptions);

    return {
      token,
      tokenType: "Bearer",
      expiresIn: config.jwtExpiresIn,
    };
  }

  verifyToken(token: string): TokenPayload {
    return jwt.verify(token, config.jwtSecret) as TokenPayload;
  }

  async authenticateUser(email: string, password: string): Promise<LoginResult> {
    const normalizedEmail = email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user || !user.passwordHash) {
      // Execute timing safe dummy compare
      await bcrypt.compare(password, DUMMY_HASH);
      throw new Error("Email atau kata sandi tidak valid.");
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new Error("Email atau kata sandi tidak valid.");
    }

    const safeUser: SafeUser = {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };

    const tokens = this.generateToken(safeUser);

    return {
      user: safeUser,
      tokens,
    };
  }

  async getUserById(id: string): Promise<SafeUser | null> {
    const user = await prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      return null;
    }

    return {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    };
  }
}

export const authService = new AuthService();
