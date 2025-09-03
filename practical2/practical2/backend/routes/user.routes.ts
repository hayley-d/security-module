import jwt from "jsonwebtoken";
import { Router } from "express";
import type { Request } from "express";

import { authMiddleware } from "../middleware/auth.middleware";
import type { APPLICATION_DB as DB } from "../db/db";
import {
  createUser,
  login,
  validateUserOtp,
  approveUser,
  validateMfa,
  getUserList, getUserById,
} from "../repositories/user.repo";
import type {
  MfaResponse,
  CreateUserDTO,
  RequestUserOption,
  ValidateOtpDto,
  ApproveUserDto,
  UpdateUserRoleDto,
} from "../types/user.types";
import {
  ApproveUserSchema,
  CreateUserDTOSchema,
  UpdateUserRoleSchema,
  UserLoginDto,
  UserLoginSchema,
  validateMfaDto,
  ValidateMfaSchema,
  ValidateOtpSchema,
} from "../schemas/user.schema";
import {UUID} from "../types";

const router = Router();

export default function userRoutes(db: DB) {
  router.get("/list", async (req, res) => {
    const list = await getUserList(db);

    if (!list || !list.ok) {
      return res.status(404).send("Not Found");
    }

    return res.status(200).json(list.items);
  });

  router.get("/users/:user_id", authMiddleware, async (req, res) => {
    try {
      const user = await getUserById(db, req.params.user_id! as UUID);

      if (!user) {
        return res.status(400).json({ error: "Invalid user" });
      }
      return res
          .status(200)
          .json({ user_id: user.user_id, email: user.email, first_name: user.first_name, last_name: user.last_name, role_id: user.role_id });
    } catch (err) {
      return res
          .status(500)
          .json({ ok: false, error: "Internal server error" });
    }
  });

  router.post("/register", async (req: Request<{}, {}, CreateUserDTO>, res) => {
    try {
      const parsed = CreateUserDTOSchema.safeParse(req.body);

      if (!parsed.success) {
        console.error("Invalid payload")
        return res.status(400).json({ error: "Invalid payload" });
      }

      const result: MfaResponse = await createUser(db, req.body);

      if (!result.ok) {
        console.error("Failed to create user", result.error)
        return res.status(400).json({ error: "Failed to create user" });
      }

      return res
        .status(201)
        .json({ user_email: result.user_email, url: result.url });
    } catch (err) {
      // @ts-ignore
      console.error("Internal Server Error", err.message)
      return res
        .status(500)
        .json({ ok: false, error: "Internal server error" });
    }
  });

  router.post(
    "/two_factor",
    async (req: Request<{}, {}, validateMfaDto>, res) => {
      try {
        const parsed = ValidateMfaSchema.safeParse(req.body);

        if (!parsed.success) {
          return res.status(400).json({ error: parsed.error.flatten });
        }

        const result = await validateMfa(db, parsed.data);

        if (!result.ok) {
          return res.status(400).json({ error: result.error });
        }

        const token = jwt.sign(
          {
            user_id: result.user?.user_id,
            user_email: result.user?.email,
            role_id: result.user?.role_id,
          },
          process.env.JWT_SECRET!,
          { expiresIn: "1h" },
        );

        return res.status(200).json({
          ok: true,
          token,
        });
      } catch (err) {
        return res
          .status(500)
          .json({ ok: false, error: "Internal server error" });
      }
    },
  );

  router.post("/login", async (req: Request<{}, {}, UserLoginDto>, res) => {
    const parsed = UserLoginSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten });
    }

    const result: RequestUserOption = await login(db, parsed.data);

    if (!result.ok) {
      return res.status(400).json(result);
    }

    return res.status(201).json({
      mfa_required: true,
      user_id: result.user?.user_id,
      user_email: result.user?.email,
    });
  });

  router.post("/verify", async (req: Request<{}, {}, ValidateOtpDto>, res) => {
    const parsed = ValidateOtpSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten });
    }

    const result = await validateUserOtp(db, req.body);

    if (!result.ok) {
      return res.status(400).json(result);
    }

    const token = jwt.sign(
      {
        user_id: result.user?.user_id,
        user_email: result.user?.email,
        role_id: result.user?.role_id,
      },
      process.env.JWT_SECRET!,
      { expiresIn: "1h" },
    );

    return res.json({
      ok: true,
      user: result.user,
      token,
    });
  });

  return router;
}
