import { Router } from "express";
import type { Request } from "express";

import { authMiddleware } from "../middleware/auth.middleware";
import type { APPLICATION_DB as DB } from "../db/db";

import {
  AssetPatchSchema,
  createDocumentDto,
  createDocumentSchema,
  PatchAssetDto,
} from "../schemas/asset.schema";
import {
  createAsset,
  deleteAsset,
  getAssetByID,
  updateAsset,
} from "../services/asset.service";
import { GetAssetOption } from "../types/asset.types";
import { getAssetList } from "../repositories/asset.repo";

const router = Router();

export function documentRoutes(db: DB) {
  router.get("/documents/list", authMiddleware, async (req, res) => {
    try {
      const result = await getAssetList(db, "document");

      if (!result.ok) {
        return res.status(400).json({ error: result.error });
      }

      return res.status(200).json(result.items);
    } catch (err) {
      return res
        .status(500)
        .json({ ok: false, error: "Internal server error" });
    }
  });

  router.get("/documents/:asset_id", authMiddleware, async (req, res) => {
    const { asset_id } = req.params;
    // @ts-ignore
    const user_id = req.user.user_id;

    if (!asset_id) {
      return res
        .status(400)
        .json({ error: "Unable to parse request payload." });
    }

    const result: GetAssetOption = await getAssetByID(db, {
      asset_id: asset_id,
      user_id: user_id,
    });

    if (!result.ok) {
      return res.status(400).json(result);
    }

    return res.status(200).json(result);
  });

  router.post(
    "/documents/",
    authMiddleware,
    async (req: Request<{}, {}, createDocumentDto>, res) => {
      console.log("Making it here");
      const parsed = createDocumentSchema.safeParse(req.body);

      if (!parsed.success) {
        console.log("error parsing payload", parsed.error);
        return res.status(400).json({ error: parsed.error.flatten });
      }

      const result = await createAsset(db, parsed.data);

      if (!result.ok) {
        console.log("Error creating asset");
        return res.status(400).json(result);
      }

      return res.status(201).send();
    },
  );

  router.patch(
    "/documents/",
    authMiddleware,
    async (req: Request<{}, {}, PatchAssetDto>, res) => {
      const parsed = AssetPatchSchema.safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.flatten });
      }

      const result = await updateAsset(db, parsed.data);

      if (!result.ok) {
        return res.status(404).json(result.error);
      }

      return res.status(200).send();
    },
  );

  router.delete("/documents/:asset_id", authMiddleware, async (req, res) => {
      console.log("DELETE DOCUMENT", req.params.asset_id);
    const { asset_id } = req.params;
    // @ts-ignore
    const user_id: string = req.user.user_id;

    const result = await deleteAsset(db, {
      asset_id: asset_id!,
      deleted_by: user_id,
    });

    if (!result.ok) {
        console.error("Error deleting asset", result.error);
      return res.status(404).json("Failed to delete asset");
    }

    return res.status(200).send();
  });

  return router;
}
