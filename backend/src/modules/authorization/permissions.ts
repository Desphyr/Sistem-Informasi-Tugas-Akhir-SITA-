import { UserRole } from "@prisma/client";

export enum Permission {
  // Administrator permissions
  MANAGE_USERS = "manage:users",
  VIEW_AUDIT_LOG = "view:audit_log",
  SYSTEM_CONFIGURE = "system:configure",

  // Lecturer / Supervisor permissions
  MANAGE_SLOTS = "manage:slots",
  VERIFY_LOGBOOK = "verify:logbook",
  MANAGE_REVISIONS = "manage:revisions",
  VIEW_SUPERVISED_STUDENTS = "view:supervised_students",

  // Student permissions
  VIEW_OWN_SUPERVISION = "view:own_supervision",
  REQUEST_SCHEDULE = "request:schedule",
  SUBMIT_DRAFT = "submit:draft",
  VIEW_OWN_LOGBOOK = "view:own_logbook",

  // Common authenticated permissions
  VIEW_PROFILE = "view:profile",
}

export const ROLE_PERMISSIONS: Record<UserRole, readonly Permission[]> = {
  [UserRole.ADMIN]: [
    Permission.MANAGE_USERS,
    Permission.VIEW_AUDIT_LOG,
    Permission.SYSTEM_CONFIGURE,
    Permission.MANAGE_SLOTS,
    Permission.VERIFY_LOGBOOK,
    Permission.MANAGE_REVISIONS,
    Permission.VIEW_SUPERVISED_STUDENTS,
    Permission.VIEW_OWN_SUPERVISION,
    Permission.REQUEST_SCHEDULE,
    Permission.SUBMIT_DRAFT,
    Permission.VIEW_OWN_LOGBOOK,
    Permission.VIEW_PROFILE,
  ],
  [UserRole.SUPERVISOR]: [
    Permission.MANAGE_SLOTS,
    Permission.VERIFY_LOGBOOK,
    Permission.MANAGE_REVISIONS,
    Permission.VIEW_SUPERVISED_STUDENTS,
    Permission.VIEW_PROFILE,
  ],
  [UserRole.STUDENT]: [
    Permission.VIEW_OWN_SUPERVISION,
    Permission.REQUEST_SCHEDULE,
    Permission.SUBMIT_DRAFT,
    Permission.VIEW_OWN_LOGBOOK,
    Permission.VIEW_PROFILE,
  ],
};
