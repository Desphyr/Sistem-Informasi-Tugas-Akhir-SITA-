export interface AppConfig {
  port: number;
  jwtSecret: string;
  jwtExpiresIn: string;
}

const defaultPort = 3000;
const parsedPort = Number(process.env.PORT ?? defaultPort);

if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

const jwtSecret = process.env.JWT_SECRET || "sita_dev_jwt_secret_key_change_in_production";
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || "24h";

export const config: AppConfig = {
  port: parsedPort,
  jwtSecret,
  jwtExpiresIn,
};
