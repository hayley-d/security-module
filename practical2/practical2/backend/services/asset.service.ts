import type { APPLICATION_DB as DB } from "../db/db";
import type { UUID } from "../types";
import { randomUUID } from "crypto";
import {
  createConfidentialAsset,
  createPublicAsset,
  getAssetBytes,
  softDeleteAsset,
  updateAssetMeta,
  updateConfidentialAsset as updateConfidentialAssetRepo,
} from "../repositories/asset.repo";

import {
  GetAssetOption,
  GetConfidentialAssetOption,
  RequestAssetOption,
  RequestOption,
} from "../types/asset.types";
import {
  CreateAssetDto,
  createConfidentialDto,
  createDocumentDto,
  DeleteAssetDto,
  PatchAssetDto,
  ReadAssetDto,
  UpdateConfidentialAsset,
} from "../schemas/asset.schema";
import { getUserById } from "../repositories/user.repo";
import { roleHasPermission } from "../repositories/role.repo";
import { User } from "../schemas/user.schema";

export async function getAssetByID(
  db: DB,
  props: ReadAssetDto,
): Promise<GetAssetOption> {
  const user: User | null = await getUserById(db, props.user_id as UUID);
  const asset: GetAssetOption = await getAssetBytes(db, props.asset_id as UUID);

  if (!user) {
    console.error("Unable to find user");
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  if (asset.asset_type === "confidential") {
    const hasPermissions = await roleHasPermission(
      db,
      user.role_id,
      "view_conf",
    );

    if (!hasPermissions) {
      console.log("User does not have permission");
      return {
        ok: false,
        error: "Failed to view asset, the user does not have permission.",
      };
    }
  } else {
    const permission =
      asset.asset_type === "image" ? "create_image" : "view_doc";

    const hasPermissions = await roleHasPermission(
      db,
      user.role_id,
      permission,
    );

    if (!hasPermissions) {
      return {
        ok: false,
        error: "Failed to fetch asset, the user does not have permission.",
      };
    }
  }

  return asset;
}

export async function createConfidentialAssetService(
  db: DB,
  asset: createConfidentialDto,
): Promise<RequestOption> {
  const user: User | null = await getUserById(db, asset.created_by as UUID);

  if (!user) {
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  const assetId: UUID = randomUUID() as UUID;

  const hasPermissions = await roleHasPermission(
    db,
    user.role_id,
    "create_conf",
  );

  if (!hasPermissions) {
    console.error("Unable to create asset, the user does not have permission.");
    return {
      ok: false,
      error: "Failed to create asset, the user does not have permission.",
    };
  }

  return await createConfidentialAsset(db, assetId, asset);
}

export async function createAsset(
  db: DB,
  asset: CreateAssetDto,
): Promise<RequestOption> {
  const user: User | null = await getUserById(db, asset.created_by as UUID);

  if (!user) {
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  const assetId: UUID = randomUUID() as UUID;

  const permission =
    asset.asset_type === "image" ? "create_image" : "create_doc";

  const hasPermissions = await roleHasPermission(db, user.role_id, permission);

  if (!hasPermissions) {
    return {
      ok: false,
      error: "Failed to create asset, the user does not have permission.",
    };
  }

  return await createPublicAsset(db, assetId, asset);
}

export async function getAsset(
  db: DB,
  assetId: UUID,
): Promise<GetAssetOption | GetConfidentialAssetOption> {
  return getAssetBytes(db, assetId);
}

export async function updateAsset(
  db: DB,
  patch: PatchAssetDto,
): Promise<RequestOption> {
  const user: User | null = await getUserById(db, patch.updated_by as UUID);

  if (!user) {
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  const permission =
    patch.asset_type === "image" ? "update_image" : "update_doc";

  const hasPermissions = await roleHasPermission(db, user.role_id, permission);

  if (!hasPermissions) {
    return {
      ok: false,
      error: "Failed to update asset, the user does not have permission.",
    };
  }

  return updateAssetMeta(db, patch);
}

export async function updateConfidentialAsset(
  db: DB,
  asset: UpdateConfidentialAsset,
): Promise<RequestOption> {
  const user: User | null = await getUserById(db, asset.updated_by as UUID);

  if (!user) {
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  const hasPermissions = await roleHasPermission(
    db,
    user.role_id,
    "update_conf",
  );

  if (!hasPermissions) {
    return {
      ok: false,
      error: "Failed to update asset, the user does not have permission.",
    };
  }

  return updateConfidentialAssetRepo(db, asset);
}

/**
 * Checks if the user roles are correct then deletes the asset.
 * @param db
 * @param props
 */
export async function deleteAsset(
  db: DB,
  props: DeleteAssetDto,
): Promise<RequestOption> {
  const user: User | null = await getUserById(db, props.deleted_by as UUID);
  const asset = await getAsset(db, props.asset_id as UUID);

  if (!asset || !asset.ok) {
    return { ok: false, error: "Failed to find asset to delete." };
  }

  if (!user) {
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  let permission = "";
  if (asset && asset.asset_type == "image") {
    permission = "delete_image";
  } else if (asset && asset.asset_type === "document") {
    permission = "delete_doc";
  } else {
    permission = "delete_conf";
  }

  const hasPermissions = await roleHasPermission(db, user.role_id, permission);

  if (!hasPermissions) {
    return {
      ok: false,
      error: "Failed to delete asset, the user does not have permission.",
    };
  }

  return softDeleteAsset(db, props);
}

export async function getConfidentialAssetByID(
  db: DB,
  props: ReadAssetDto,
): Promise<GetConfidentialAssetOption> {
  const user: User | null = await getUserById(db, props.user_id as UUID);
  const asset: GetAssetOption = await getAssetBytes(db, props.asset_id as UUID);

  if (!user) {
    return {
      ok: false,
      error: "Failed to find user that requested delete operation.",
    };
  }

  const hasPermissions = await roleHasPermission(db, user.role_id, "view_conf");

  if (!hasPermissions) {
    return {
      ok: false,
      error: "Failed to view asset, the user does not have permission.",
    };
  }

  return asset;
}
