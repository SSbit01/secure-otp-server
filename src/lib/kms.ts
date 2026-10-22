import { deleteKek, getCurrentKekId, getKek, storeKek } from "@/custom/kms";
import { BASE64URL_OPTIONS } from "@/lib/base64";
import { KEK_ID_LENGTH } from "@/lib/calculations";
import { WRAPPED_DEK_BYTES, createKek, generateRandomId, unwrapKey } from "@/lib/crypto";
import { regexBase64Url } from "@/lib/regex";
import type { Context } from "hono";

export const KEK_ID_BYTES: number = 12;

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
