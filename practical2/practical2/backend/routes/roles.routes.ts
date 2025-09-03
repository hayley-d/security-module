import { Router } from "express";
import type { APPLICATION_DB as DB } from "../db/db";

import type { Request } from "express";
import { authMiddleware } from "../middleware/auth.middleware";
import { HasAccessDto, hasAccessSchema } from "../schemas/roles.schema";
import { roleHasPermission } from "../repositories/role.repo";
import {
  approveUser,
  getUserById,
  updateUserRole,
} from "../repositories/user.repo";
import { getRoleByName } from "../repositories/role.repo";
import { RoleOption } from "../types/role.types";
import {UUID} from "../types";

const router = Router();

export default function rolesRoutes(db: DB) {
  router.post(
    "/has_access",
    authMiddleware,
    async (req: Request<{}, {}, HasAccessDto>, res) => {
      // @ts-ignore
      const role_id = req.user.role_id;
      // @ts-ignore
      const user = await getUserById(db, req.user.user_id);
      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }
      const parsed = hasAccessSchema.safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.flatten });
      }

      const result = await roleHasPermission(
        db,
        user.role_id,
        parsed.data.permission,
      );

      if (!result) {
        return res.status(400).json(result);
      }

      return res.status(200).json(result);
    },
  );

  router.get("/check_role", authMiddleware, async (req, res) => {
    // @ts-ignore
    const role_id: string = req.user.role_id;

    const role1: RoleOption = await getRoleByName(db, "Manager");
    const role2: RoleOption = await getRoleByName(db, "Admin");

    if (!role1.ok || !role2.ok) {
      return res.status(404).json({ error: "Role not found." });
    }

    if (role1.role?.role_id === role_id || role2.role?.role_id === role_id) {
      return res.status(200).send();
    }

    return res.status(403).send();
  });

    router.patch(
        "/manage",
        authMiddleware,
        async (req: Request<{}, {}, { user_id: string }>, res) => {
            // @ts-ignore
            const user = await getUserById(db, req.body.user_id);

            if (!user) {
                return res.status(404).json({ error: "User not found." });
            }

            const result = await approveUser(db, user.user_id);

            if (!result.ok) {
                return res.status(500).send();
            }

            return res.status(200).send();
        },
    );

  router.patch(
    "/approve",
    authMiddleware,
    async (req: Request<{}, {}, { user_id: string }>, res) => {
      // @ts-ignore
      const user = await getUserById(db, req.body.user_id);

      if (!user) {
        return res.status(404).json({ error: "User not found." });
      }

      const result = await approveUser(db, user.user_id);

      if (!result.ok) {
        return res.status(500).send();
      }

      return res.status(200).send();
    },
  );

  router.patch(
    "/update_role",
    authMiddleware,
    async (req: Request<{}, {}, { user_id: string; role_id: string }>, res) => {
      // @ts-ignore
      const result = await updateUserRole(db, {
        user_id: req.body.user_id as UUID,
        role_id: req.body.role_id as UUID,
      });

      if (!result.ok) {
        return res.status(500).send();
      }

      return res.status(200).send();
    },
  );
  return router;
}
