import { randomUUID } from "crypto";
import { authenticator } from "otplib";
import type { APPLICATION_DB as DB } from "../db/db";
import type { UUID, Email } from "../types";
import {
  generateTotpSecret,
  getGuestRoleId,
  hashPassword,
  validateAndNormalizeEmail,
  validatePassword,
  verifyPassword,
} from "../services/user.service";
import type {
  ApproveUserDto,
  CreateUserDTO,
  MfaResponse,
  RequestOption,
  RequestUserOption,
  UpdateFailedUserSignInDto,
  UpdateUserRoleDto,
  UpdateUserSignInDto,
  ValidateMfaDto,
  ValidateOtpDto,
} from "../types/user.types";

import { getRoleById } from "../services/role.service";
import {
  ListUser,
  ListUserSchema,
  User,
  UserLoginDto,
  UserSchema,
  validateMfaDto,
} from "../schemas/user.schema";
import { getRoleByName } from "./role.repo";

export async function getUserById(db: DB, userId: UUID): Promise<User | null> {
  const row = await db.get<User>("SELECT * FROM users WHERE user_id = ?", [
    userId.toString(),
  ]);

  return row ? row : null;
}

export async function getUserList(
  db: DB,
): Promise<{ ok: boolean; items: ListUser[] }> {
  const rows = await db.all<User>(
    `SELECT first_name, last_name, role_id, user_id, email FROM users WHERE first_name <> 'anonymous'`,
    [],
  );

  if (!rows) {
    return { ok: false, items: [] };
  }

  const parsedRows: ListUser[] = rows.map((row) => ListUserSchema.parse(row));

  return { ok: true, items: parsedRows };
}

export async function getUserByEmail(
  db: DB,
  email: Email,
): Promise<User | null> {
  const row = await db.get<User>(`SELECT * FROM users WHERE email = ?`, [
    email.toLowerCase(),
  ]);
  return row ? row : null;
}

export async function createUser(
  db: DB,
  dto: CreateUserDTO,
): Promise<MfaResponse> {
  const validated_email = validateAndNormalizeEmail(dto.email);

  if (!validated_email.ok) {
    console.error("Invalid email address");
    return { ok: false, error: "Invalid email address" };
  }
  const email = validated_email.email as Email;

  const validate_psw = validatePassword(dto.password);
  if (!validate_psw.ok) {
    console.error("Invalid password");
    return { ok: false, error: "Invalid password" };
  }

  const psw_hash = await hashPassword(dto.password);

  const uuid = randomUUID();
  const { secret, url } = generateTotpSecret(email);
  const guest_role_id = await getGuestRoleId(db);

  await db.run(
    `INSERT INTO users (
       user_id, first_name, last_name, email, password_hash,
       created_at, is_approved, sign_in_count, failed_login_attempts,
       role_id, mfa_totp_secret 
     ) VALUES (?, ?, ?, ?, ?, unixepoch(), false, 0, 0, ?, ?)`,
    [
      uuid,
      dto.first_name,
      dto.last_name,
      email,
      psw_hash,
      guest_role_id,
      secret,
    ],
  );

  return {
    ok: true,
    user_email: email,
    url: url,
  };
}

export async function updateUserRole(
  db: DB,
  dto: UpdateUserRoleDto,
): Promise<RequestOption> {
  const role = await getRoleById(db, dto.role_id);
  const user = await getUserById(db, dto.user_id);
  if (!role) {
    return { ok: false, error: "Role not found." };
  }
  if (!user) {
    return { ok: false, error: "User not found." };
  }

  await db.run("UPDATE users SET role_id = ? WHERE user_id = ?", [
    dto.role_id,
    dto.user_id,
  ]);

  return { ok: true };
}

export async function approveUser(
  db: DB,
  user_id: string,
): Promise<RequestOption> {
  const role = await getRoleByName(db, "User");
  const user = await getUserById(db, user_id as UUID);


  if (!role || !role.ok) {
    return { ok: false, error: "Role not found." };
  }

  if (!user) {
    return { ok: false, error: "User not found." };
  }

  await db.run("UPDATE users SET role_id = ? WHERE user_id = ?", [
    role.role?.role_id,
    user_id,
  ]);

  return { ok: true };
}

export async function bumpLoginSuccess(
  db: DB,
  dto: UpdateUserSignInDto,
): Promise<RequestOption> {
  const user = await getUserById(db, dto.user_id);
  if (!user) {
    return { ok: false, error: "User not found." };
  }

  await db.run(
    `UPDATE users SET 
                                   failed_login_attempts = 0, 
                                   sign_in_count = sign_in_count + 1, 
                                   last_login = unixepoch(), 
                                   last_sign_in_ip = current_sign_in_ip, 
                                   current_sign_in_ip = ? 
                  WHERE user_id = ?`,
    [dto.current_ip, dto.user_id],
  );

  return { ok: true };
}

export async function bumpLoginFailure(
  db: DB,
  dto: UpdateFailedUserSignInDto,
): Promise<RequestOption> {
  const user = await getUserById(db, dto.user_id);
  if (!user) {
    return { ok: false, error: "User not found." };
  }
  await db.run(
    `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE user_id = ?`,
    [dto.user_id],
  );
  return { ok: true };
}

export async function login(
  db: DB,
  dto: UserLoginDto,
): Promise<RequestUserOption> {
  const user: User | null = await getUserByEmail(db, dto.user_email as Email);

  if (!user) {
    return { ok: false, error: "Invalid login credentials." };
  }

  const user_role = await getRoleById(db, user.role_id as UUID);

  if(!user_role || user_role.role_name == "Guest") {
    return { ok: false, error: "User not approved." };
  }

  const isSetup = await isMfaSetup(db, user.user_id as UUID);
  if (!isSetup) {
    return { ok: false, error: "MFA not setup" };
  }

  const isValidPassword = await verifyPassword(
    dto.password,
    user.password_hash,
  );

  if (!isValidPassword) {
    return { ok: false, error: "Invalid login credentials." };
  }

  return { ok: true, user };
}

export async function validateUserOtp(
  db: DB,
  dto: ValidateOtpDto,
): Promise<RequestUserOption> {
  const user: User | null = await getUserByEmail(db, dto.user_email);
  if (!user) {
    return { ok: false, error: "User not found." };
  }

  const otp = dto.otp.trim();

  if (user && user.mfa_totp_secret) {
    const ok = authenticator.verify({
      token: otp,
      secret: user.mfa_totp_secret,
    });
    if (!ok) {
      await bumpLoginFailure(db, { user_id: user.user_id as UUID });
      return { ok: false, error: "Invalid OTP." };
    }
  }

  await bumpLoginSuccess(db, {
    user_id: user.user_id as UUID,
    current_ip: dto.current_ip,
  });
  return { ok: true, user };
}

export async function validateMfa(
  db: DB,
  dto: validateMfaDto,
): Promise<RequestUserOption> {
  const user: User | null = await getUserByEmail(db, dto.user_email as Email);
  if (!user || !user.mfa_totp_secret) {
    return { ok: false, error: "User not found." };
  }

  const ok = authenticator.verify({
    token: dto.token.trim(),
    secret: user.mfa_totp_secret,
  });
  if (!ok) {
    return { ok: false, error: "Invalid OTP." };
  }

  await db.run(
    `UPDATE users SET mfa_enrolled_at = unixepoch() WHERE user_id = ?`,
    [user.user_id],
  );

  return { ok: true, user: user };
}

export async function isMfaSetup(db: DB, userId: UUID): Promise<boolean> {
  const row = await db.get<{ ok: number }>(
    `SELECT EXISTS(
            SELECT 1 FROM users
            WHERE user_id = ?
              AND mfa_enrolled_at IS NOT NULL
        ) AS ok`,
    [userId],
  );
  return !!row && row.ok === 1;
}
