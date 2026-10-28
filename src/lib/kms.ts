import { deleteKek, getCurrentKekId, getKek, storeKek } from "#src/custom/kms";
import { BASE64URL_OPTIONS, bytesToBase64Length, regexBase64Url } from "#src/lib/base64";
import { createKek, generateRandomId, unwrapKey, WRAPPED_DEK_BYTES } from "#src/lib/crypto";
import type { Context } from "hono";

export const KEK_ID_BYTES: number = 12;

export const KEK_ID_LENGTH: number = bytesToBase64Length(KEK_ID_BYTES);

export const ENVELOPE_ENCRYPTION_WRAP_LENGTH = KEK_ID_LENGTH + bytesToBase64Length(WRAPPED_DEK_BYTES);

export async function getDek(c: Context, kekId: string, wrappedDekString: string): Promise<CryptoKey | undefined> {
  if (kekId.length !== KEK_ID_LENGTH || !regexBase64Url.test(kekId)) {
    return;
  }

  const kek = await getKek(c, kekId);

  if (!kek) {
    return;
  }

  let wrappedDek: Uint8Array<ArrayBuffer>;

  try {
    wrappedDek = Uint8Array.fromBase64(wrappedDekString, BASE64URL_OPTIONS);
  } catch {
    return;
  }

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    return;
  }

  return await unwrapKey(wrappedDek, kek);
}

export async function rotateKek(c: Context, kekId: string) {
  const currentKekId = await getCurrentKekId(c);

  if (!currentKekId || kekId === currentKekId) {
    console.warn("A KEK rotation has been triggered.");
    await storeKek(c, await createKek(), generateRandomId(KEK_ID_BYTES).toBase64(BASE64URL_OPTIONS));
    console.log("KEK rotation completed.");
  }

  await deleteKek(c, kekId);
}
