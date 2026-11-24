export interface LoginInput {
  email: string;
  password: string;
}

export interface ValidationResult {
  valid: boolean;
  message?: string;
  data?: LoginInput;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateLoginInput(payload: unknown): ValidationResult {
  if (!payload || typeof payload !== "object") {
    return {
      valid: false,
      message: "Request body harus berupa JSON object yang valid.",
    };
  }

  const { email, password } = payload as Record<string, unknown>;

  if (typeof email !== "string" || !email.trim()) {
    return {
      valid: false,
      message: "Email wajib diisi.",
    };
  }

  if (!EMAIL_REGEX.test(email.trim())) {
    return {
      valid: false,
      message: "Format email tidak valid.",
    };
  }

  if (typeof password !== "string" || !password.trim()) {
    return {
      valid: false,
      message: "Kata sandi wajib diisi.",
    };
  }

  return {
    valid: true,
    data: {
      email: email.trim().toLowerCase(),
      password,
    },
  };
}
