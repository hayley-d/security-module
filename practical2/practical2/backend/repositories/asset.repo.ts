import type { APPLICATION_DB as DB } from "../db/db";
import crypto from "crypto";
import path from "path";
import dotenv from "dotenv";

import { UUID } from "../types";
import {
  AssetListOptions,
  GetAssetOption,
  GetConfidentialAssetOption,
  ListAssetsOption,
  RequestAssetOption,
  RequestOption,
} from "../types/asset.types";
import {
  Asset,
  assetSchema,
  CreateAssetDto,
  DeleteAssetDto,
  ListAssetItem,
  ListAssetItemSchema,
  PatchAssetDto,
  UpdateConfidentialAsset,
} from "../schemas/asset.schema";

dotenv.config({ path: path.resolve(__dirname, "../.env") });
const MASTER_KEY_HEX = process.env.MASTER_KEY;
if (!MASTER_KEY_HEX) {
  throw new Error("MASTER_KEY not set in .env");
}
export const MASTER_KEY = Buffer.from(MASTER_KEY_HEX, "hex");

/**
 * Utility function to compute the SHA-256 hash of a file/asset.
 * @param buf
 */
function sha256Hex(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * HMAC-based Key Derivation Function.
 * It takes the master key, key id/version, and asset id to derive a unique 256-bit key per asset.
 * @param masterKey
 * @param keyId
 * @param assetId
 */
function hkdf32(masterKey: Buffer, keyId: string, assetId: string): Buffer {
  const arr = crypto.hkdfSync(
    "sha256",
    masterKey,
    Buffer.from(assetId, "utf8"),
    Buffer.from(`asset-data:${keyId}`, "utf8"),
    32,
  );
  return Buffer.from(arr);
}

export async function getAsset(
  db: DB,
  assetId: UUID,
): Promise<RequestAssetOption> {
  const row: Asset | undefined = await db.get<Asset>(
    `SELECT * FROM asset WHERE asset_id = ? AND deleted_at IS NULL`,
    [assetId],
  );
  if (!row) {
    return { ok: false, error: "Failed to find asset" };
  }

  const parsed = assetSchema.parse(row);

  return parsed
    ? { ok: true, asset: parsed }
    : { ok: false, error: "Error fetching asset from the database" };
}

export async function listAssets(
  db: DB,
  opts: AssetListOptions = {},
): Promise<Asset[]> {
  const { type, limit = 10, offset = 0 } = opts;

  const rows = await db.all<Asset>(
    `SELECT * FROM asset
       ${type ? "WHERE asset_type = ?" : ""}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
    type ? [type, limit, offset] : [limit, offset],
  );

  return rows.map((row) => assetSchema.parse(row));
}

/**
 * Created a public asset type being either a document or image.
 * @param db
 * @param assetId
 * @param asset
 */
export async function createPublicAsset(
  db: DB,
  assetId: UUID,
  asset: CreateAssetDto,
): Promise<RequestOption> {
  const sha = sha256Hex(asset.content);
  const result = await db.run(
    `INSERT INTO asset (
       asset_id, description, asset_type,
       file_name, mime_type, size_bytes, sha256,
       content, created_at, created_by
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch(), ?)`,
    [
      assetId,
      asset.description,
      asset.asset_type,
      asset.file_name,
      asset.mime_type,
      asset.content.length,
      sha,
      asset.content,
      asset.created_by,
    ],
  );

  if (!result || result.changes === 0) {
    return { ok: false, error: "Failed to create public asset" };
  }

  return { ok: true };
}

export async function getAssetList(
  db: DB,
  assetType: "image" | "confidential" | "document",
): Promise<ListAssetsOption> {
  const rows = await db.all<Asset>(
    `SELECT asset_id, file_name, description FROM asset WHERE asset_type = ? AND deleted_at IS NULL`,
    [assetType],
  );

  if (!rows) {
    return {
      ok: false,
      error: `Unable to find assets of type ${assetType} in the database`,
    };
  }

  const parsedRows: ListAssetItem[] = rows.map((row) =>
    ListAssetItemSchema.parse(row),
  );

  return { ok: true, items: parsedRows };
}

/**
 * Adds a confidential asset to the database.
 * @param db
 * @param assetId
 * @param asset
 */
export async function createConfidentialAsset(
  db: DB,
  assetId: UUID,
  asset: CreateAssetDto,
): Promise<RequestOption> {
  const keyId = asset.key_id ?? "v1";
  const dataKey = hkdf32(MASTER_KEY, keyId, assetId);

  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dataKey, nonce);
  const aad = Buffer.from(`${assetId}|confidential|${asset.mime_type}`, "utf8");
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(asset.content),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const sha = sha256Hex(asset.content);

  const response = await db.run(
    `INSERT INTO asset (
       asset_id, description, asset_type,
       file_name, mime_type, size_bytes, sha256,
       payload_ciphertext, payload_nonce, payload_tag, key_id,
       created_at, created_by
     ) VALUES (?, ?, 'confidential', ?, ?, ?, ?, ?, ?, ?, ?, unixepoch(), ?)`,
    [
      assetId,
      asset.description ?? null,
      asset.file_name ?? null,
      asset.mime_type,
      asset.content.length,
      sha,
      ciphertext,
      nonce,
      tag,
      keyId,
      asset.created_by,
    ],
  );

  if (!response || response.changes === 0) {
    return { ok: false, error: "Failed to create confidential asset" };
  }

  return { ok: true };
}

/**
 * Fetches an asset from the database and decrypts it if of confidential type.
 * @param db
 * @param assetId
 */
export async function getAssetBytes(
  db: DB,
  assetId: UUID,
): Promise<GetAssetOption | GetConfidentialAssetOption> {
  const row = await db.get<Asset>(
    `SELECT file_name, description, mime_type, asset_type, content,
            payload_ciphertext, payload_nonce, payload_tag, key_id
     FROM asset WHERE asset_id = ? AND deleted_at IS NULL`,
    [assetId],
  );

  if (!row) {
    return { ok: false, error: "Unable to find asset in the database" };
  }

  if (row.asset_type !== "confidential") {
    if (row.content) {
      return {
        ok: true,
        mimeType: row.mime_type,
        bytes: row.content!,
        description: row.description!,
        file_name: row.file_name!,
        asset_type: row.asset_type!,
      };
    } else {
      return { ok: false, error: "Asset content not found" };
    }
  }

  const dataKey = hkdf32(MASTER_KEY, row.key_id!, assetId);

  if (!row.payload_nonce) {
    return { ok: false, error: "Asset is missing decrypt metadata" };
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    dataKey,
    row.payload_nonce,
  );

  const aad = Buffer.from(`${assetId}|confidential|${row.mime_type}`, "utf8");

  decipher.setAAD(aad);

  if (!row.payload_tag) {
    return { ok: false, error: "Asset is missing decrypt metadata" };
  }

  decipher.setAuthTag(row.payload_tag);
  const decrypted = Buffer.concat([
    decipher.update(row.payload_ciphertext!),
    decipher.final(),
  ]);
  const content = decrypted.toString("utf8");

  return {
    ok: true,
    mimeType: row.mime_type,
    asset_type: row.asset_type,
    content: content,
    description: row.description!,
    file_name: row.file_name!,
  };
}

/**
 * Soft deletes an asset from the database.
 * @param db
 * @param props
 */
export async function softDeleteAsset(
  db: DB,
  props: DeleteAssetDto,
): Promise<RequestOption> {
  const result = await db.run(
    `UPDATE asset SET deleted_by = ?, deleted_at = unixepoch() WHERE asset_id = ? AND deleted_at IS NULL`,
    [props.deleted_by, props.asset_id],
  );

  if (!result) {
    return { ok: false, error: "Unable to find asset in the database" };
  }

  if (result.changes === 0) {
    return { ok: false, error: "Asset already deleted." };
  }

  return { ok: true };
}

/**
 * Updates an image or document asset.
 * @param db
 * @param patch
 */
export async function updateAssetMeta(
  db: DB,
  patch: PatchAssetDto,
): Promise<RequestOption> {
  const sets: string[] = [];
  const vals: any[] = [];
  const push = (c: string, v: any) => {
    sets.push(`${c} = ?`);
    vals.push(v);
  };

  if (patch.description !== undefined) push("description", patch.description);
  if (patch.file_name !== undefined) push("file_name", patch.file_name);
  if (patch.content !== undefined) {
    const sha = sha256Hex(patch.content);
    push("content", patch.content);
    push("size_bytes", patch.content.length);
    push("sha256", sha);
  }
  push("mime_type", patch.mime_type);
  push("updated_by", patch.updated_by);

  if (sets.length === 0) {
    return {
      ok: false,
      error: "Unable to update asset. No values provided to update.",
    };
  }

  vals.push(patch.asset_id);
  const result = await db.run(
    `UPDATE asset SET ${sets.join(", ")}, updated_at = unixepoch() WHERE asset_id = ?`,
    vals,
  );
  if (!result || result.changes === 0) {
    return { ok: false, error: "Unable to update asset." };
  }

  return { ok: true };
}

/**
 * Updates a confidential resource.
 * @param db
 * @param asset
 */
export async function updateConfidentialAsset(
  db: DB,
  asset: UpdateConfidentialAsset,
): Promise<RequestOption> {
  const sets: string[] = [];
  const vals: string[] = [];

  const push = (c: string, v: any) => {
    sets.push(`${c} = ?`);
    vals.push(v);
  };

  push("updated_by", asset.updated_by);

  if (asset.description) {
    push("description", asset.description);
  }

  if (asset.file_name) {
    push("file_name", asset.file_name);
  }

  if (asset.content) {
    const keyId = "v1";
    const dataKey = hkdf32(MASTER_KEY, keyId, asset.asset_id);
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", dataKey, nonce);
    const aad = Buffer.from(
      `${asset.asset_id}|confidential|application/text`,
      "utf8",
    );
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([
      cipher.update(asset.content),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    push("payload_ciphertext", ciphertext);
    push("payload_nonce", nonce);
    push("payload_tag", tag);
    push("key_id", keyId);
  }

  if (sets.length === 0) {
    return { ok: false, error: "Nothing to update." };
  }

  vals.push(asset.asset_id);

  const result = await db.run(
    `UPDATE asset SET ${sets.join(", ")}, updated_at = unixepoch() WHERE asset_id = ?`,
    vals,
  );

  if (!result || result.changes === 0) {
    return { ok: false, error: "Failed to update asset." };
  }

  return { ok: true };
}
