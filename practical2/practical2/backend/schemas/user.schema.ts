import { z } from "zod";

export const CreateUserDTOSchema = z.object({
  first_name: z.string().min(1, "First name is required"),
  last_name: z.string().min(1, "Last name is required"),
  email: z
    .string()
    .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email address"),
  password: z
      .string()
      .min(8, "Password must be at least 8 characters")
      .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
      .regex(/[0-9]/, "Password must contain at least one digit")
      .regex(/[*,$@!%]/, "Password must contain at least one special character (*,$@!%)"),
});

export const ValidateMfaSchema = z.object({
  user_email: z
    .string()
    .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email address"),
  token: z.string().nonempty(),
});

export const UserLoginSchema = z.object({
  user_email: z
      .string()
      .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email address"),
  password: z.string().min(4),
});

export const ValidateOtpSchema = z.object({
  user_email: z
      .string()
      .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email address"),
  current_ip: z.string().nonempty(),
  otp: z.string().nonempty(),
});

export const ApproveUserSchema = z.object({
  user_id: z.string().nonempty(),
});

export const UpdateUserRoleSchema = z.object({
  user_id: z.string().nonempty(),
  role_id: z.string().nonempty(),
});

const uuidV4Regex =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const UserSchema = z.object({
  user_id: z.string().regex(uuidV4Regex, "user_id must be a valid UUID v4"),
  first_name: z.string().min(1).max(50),
  last_name: z.string().min(1).max(50),
  email: z.string().email({ message: "Invalid email address" }),
  password_hash: z.string(),
  created_at: z.number().default(0),
  last_login: z.number().default(0).nullable(),
  is_approved: z
    .number()
    .default(0)
    .transform((val) => val === 1),
  sign_in_count: z.number().default(0),
  failed_login_attempts: z.number().default(0),
  current_sign_in_ip: z.string().optional().nullable(),
  last_sign_in_ip: z.string().optional().nullable(),
  role_id: z.string().regex(uuidV4Regex, "role_id must be a valid UUID v4"),
  mfa_totp_secret: z.string().nullable(),
  mfa_enrolled_at: z.number().default(0).nullable(),
});

export const ListUserSchema = z.object({
  user_id: z.string().regex(uuidV4Regex, "role_id must be a valid UUID v4"),
  first_name: z.string().min(1).max(50),
  last_name: z.string().min(1).max(50),
  email: z.string().email({ message: "Invalid email address" }),
  role_id: z.string().regex(uuidV4Regex, "role_id must be a valid UUID v4"),
});

export type CreateUserDTO = z.infer<typeof CreateUserDTOSchema>;
export type validateMfaDto = z.infer<typeof ValidateMfaSchema>;
export type UserLoginDto = z.infer<typeof UserLoginSchema>;
export type ApproveUserDto = z.infer<typeof ApproveUserSchema>;
export type User = z.infer<typeof UserSchema>;
export type ListUser = z.infer<typeof ListUserSchema>;
