/**
 * Audit Service — US-03
 *
 * Mencatat aktivitas sistem ke tabel change_logs (ChangeLog) secara append-only.
 * Hashing password, token, atau secret TIDAK boleh dan TIDAK akan dicatat ke sini.
 *
 * Catatan desain append-only:
 *  - Tidak ada metode update() atau delete() pada service ini.
 *  - Tidak ada endpoint DELETE/PATCH untuk audit log yang dipublikasikan.
 *  - Proteksi tambahan di level database (PostgreSQL Row-Level Security / trigger)
 *    direkomendasikan untuk produksi, namun berada di luar cakupan aplikasi ini.
 */

import { prisma } from "../../config/prisma.js";
import { Prisma } from "@prisma/client";
import type { ChangeLog } from "@prisma/client";

export interface AuditEntry {
  /** ID pengguna yang melakukan aksi (dari token yang diverifikasi server). Null jika sistem. */
  actorId: string | null;
  /** Jenis entitas yang terdampak, mis: "supervision", "session", "revision_item" */
  entityType: string;
  /** UUID entitas yang terdampak */
  entityId: string;
  /** Nama aksi, mis: "LOGIN", "TITLE_CHANGED", "STATUS_CHANGED" */
  action: string;
  /**
   * Data perubahan. Gunakan { field, oldValue, newValue } untuk perubahan field.
   * JANGAN masukkan password, token, secret, atau hash ke dalam objek ini.
   */
  changes?: Record<string, unknown> | null;
}

export interface AuditListOptions {
  entityType?: string;
  entityId?: string;
  actorId?: string;
  limit?: number;
  offset?: number;
}

export class AuditService {
  /**
   * Merekam satu entri audit log.
   * Kegagalan pencatatan tidak melempar exception — hanya di-log ke stderr
   * agar tidak mengganggu alur bisnis utama.
   */
  async record(entry: AuditEntry): Promise<ChangeLog | null> {
    try {
      const log = await prisma.changeLog.create({
        data: {
          actorId: entry.actorId,
          entityType: entry.entityType,
          entityId: entry.entityId,
          action: entry.action,
          changes:
            entry.changes != null
              ? (entry.changes as Prisma.InputJsonValue)
              : Prisma.NullableJsonNullValueInput.DbNull,
        },
      });
      return log;
    } catch (error: unknown) {
      // Gagal mencatat log tidak boleh crash aplikasi
      console.error("[AuditService] Gagal mencatat audit log:", error);
      return null;
    }
  }

  /**
   * Mengambil daftar audit log — hanya untuk aktor berwenang (dicek di controller/middleware).
   * Hanya mendukung operasi baca (append-only protection).
   */
  async list(options: AuditListOptions = {}): Promise<ChangeLog[]> {
    const { entityType, entityId, actorId, limit = 50, offset = 0 } = options;

    return prisma.changeLog.findMany({
      where: {
        ...(entityType ? { entityType } : {}),
        ...(entityId ? { entityId } : {}),
        ...(actorId ? { actorId } : {}),
      },
      orderBy: { createdAt: "desc" },
      take: Math.min(limit, 200), // maksimum 200 per request
      skip: offset,
    });
  }

  /**
   * Menghitung total entri — hanya untuk paginasi pada endpoint baca.
   */
  async count(options: Omit<AuditListOptions, "limit" | "offset"> = {}): Promise<number> {
    const { entityType, entityId, actorId } = options;

    return prisma.changeLog.count({
      where: {
        ...(entityType ? { entityType } : {}),
        ...(entityId ? { entityId } : {}),
        ...(actorId ? { actorId } : {}),
      },
    });
  }
}

export const auditService = new AuditService();
