import { getCookie } from "hono/cookie";
import credentialValidator from "@/custom/credential";
import finalAction from "@/custom/final";
import { deleteOtpTokenId, replaceOtpTokenId, updateOtpTokenExpires, verifyOtpTokenId } from "@/custom/id";
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms";
import { generateOtp, OTP_ALLOW_ONLY_ONE_RESENDING, OTP_ATTEMPTS_BLOCK, OTP_MAX_CREDENTIALS } from "@/custom/otp";
import sendOtp from "@/custom/send";
import { BASE64URL_OPTIONS } from "@/lib/base64";
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH, KEK_ID_LENGTH, OTP_INVALID_BLOCK_MS, OTP_RESEND_BLOCK_MS } from "@/lib/computed";
import { generateRandomId } from "@/lib/crypto/id";
import { createDek, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek";
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek";

import {
  ERR_CREDENTIAL_INVALID,
  ERR_OTP_CONFLICT,
  ERR_OTP_EXPIRED,
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_CREDENTIALS,
  ERR_OTP_VERIFICATION_NOT_ALLOWED
} from "@/lib/error/static";

import { getDek, KEK_ID_BYTES, rotateKek } from "@/lib/kms";
import { blockOtpToken, getOtpTokenData, getOtpTokenList, OTP_TOKEN_SEPARATOR } from "@/lib/otp";
import { deleteOtpCookie, getOtpCookieName, setOtpCookie } from "@/lib/otp/cookie";

import {
  ATTEMPTS,
  createEncodedOtpToken,
  CREDENTIAL,
  decodeOtpToken,
  encodeOtpToken,
  EXPIRES,
  OTP,
  OTP_BLOCK,
  RESEND_BLOCK
} from "@/lib/otp/encode/token";

import generateOtpTokenCreationResponse from "@/lib/otp/response/create";
import { getReducedTimePrecision } from "@/lib/time";
import otpCookieValidator from "@/lib/validators/otp";
import otpValueValidator from "@/lib/validators/otp";
import app from "@/setup";

import type { OtpTokenData } from "@/lib/otp";

app.post("/api/otp/create", credentialValidator, async (c) => {
  const credential = c.req.valid("form");

  const otpData = getCookie(c, getOtpCookieName(c))?.trim();

  if (!otpData) {
    return await generateOtpTokenCreationResponse(c, credential);
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH);

  let dek = await getDek(c, kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH));

  if (!dek) {
    return await generateOtpTokenCreationResponse(c, credential);
  }

  let additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);

  const encodedOtpTokenList = await getOtpTokenList(
    dek,
    otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH),
    additionalData
  );

  if (!encodedOtpTokenList) {
    return await generateOtpTokenCreationResponse(c, credential);
  }

  const id = encodedOtpTokenList.pop();

  if (!id) {
    deleteOtpCookie(c);
    await rotateKek(c, kekId);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  if (encodedOtpTokenList.length > OTP_MAX_CREDENTIALS) {
    deleteOtpCookie(c);
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  const newEncodedOtpTokenList: string[] = [];

  let currentOtpTokenData: OtpTokenData | undefined;
  let currentEncodedOtpToken = "";
  let expires = 0;

  const dateNow = Date.now();

  for (const encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken);
    if (!otpToken) {
      deleteOtpCookie(c);
      await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
      return c.json(ERR_OTP_INVALID_COOKIE, 400);
    }

    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES];
      }

      if (!currentEncodedOtpToken && credential === otpToken[CREDENTIAL]) {
        currentEncodedOtpToken = encodedOtpToken;
        currentOtpTokenData = getOtpTokenData(otpToken);
      } else {
        newEncodedOtpTokenList.push(encodedOtpToken);
      }
    }
  }

  if (newEncodedOtpTokenList.length >= OTP_MAX_CREDENTIALS) {
    return c.json(ERR_OTP_TOO_MANY_CREDENTIALS, 400);
  }

  if (!expires) {
    // All OTP tokens have expired, create a new list.
    return await generateOtpTokenCreationResponse(c, credential);
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let envelope: string;

  const currentKekId = await getCurrentKekId(c);

  if (currentKekId === kekId) {
    envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH);
  } else {
    let kek: CryptoKey | undefined;
    if (currentKekId) {
      [dek, kek] = await Promise.all([createDek(), getKek(c, currentKekId)]);
    } else {
      dek = await createDek();
    }
    if (kek) {
      // @ts-expect-error: `currentKekId` must be defined if KEK exists.
      kekId = currentKekId;
      additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS);
    } else {
      additionalData = generateRandomId(KEK_ID_BYTES);
      kekId = additionalData.toBase64(BASE64URL_OPTIONS);
      kek = await createKek();
      envelope = kekId +
        new Uint8Array(
          (await Promise.all([wrapKey(dek, kek), storeKek(c, kek, kekId)]))[0]
        ).toBase64(BASE64URL_OPTIONS);
    }
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (currentEncodedOtpToken) {
    newEncodedOtpTokenList.push(currentEncodedOtpToken);
  } else {
    /**
     * Verify OTP Token List ID before sending the OTP.
     */
    if (!await verifyOtpTokenId(c, id, expires)) {
      deleteOtpCookie(c);
      return c.json(ERR_OTP_INVALID_COOKIE, 400);
    }

    const otp = generateOtp();

    if (!await sendOtp(c, credential, otp)) {
      return c.json(ERR_CREDENTIAL_INVALID, 400);
    }

    /**
     * `updateOtpTokenExpires` is used to verify too.
     * It is set after `sendOtp()` because it takes some time.
     */
    expires = await updateOtpTokenExpires(c, id, expires);

    if (!expires) {
      deleteOtpCookie(c);
      return c.json(ERR_OTP_CONFLICT, 429);
    }

    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS;

    currentEncodedOtpToken = createEncodedOtpToken(credential, expires, otp, resendBlock);

    newEncodedOtpTokenList.push(currentEncodedOtpToken);

    currentOtpTokenData = {
      expires: new Date(getReducedTimePrecision(expires)),
      resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
    };
  }

  newEncodedOtpTokenList.push(id);

  setOtpCookie(
    c,
    envelope +
      await encryptTextSymmetrically(
        dek,
        newEncodedOtpTokenList.join(OTP_TOKEN_SEPARATOR),
        additionalData
      ),
    new Date(getReducedTimePrecision(expires))
  );

  return c.json(currentOtpTokenData);
});

app.post("/api/otp/resend", async (c) => {
  const otpData = getCookie(c, getOtpCookieName(c))?.trim();

  if (!otpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH);

  let dek = await getDek(c, kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH));

  if (!dek) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  let additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);

  const encodedOtpTokenList = await getOtpTokenList(
    dek,
    otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH),
    additionalData
  );

  if (!encodedOtpTokenList) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  const id = encodedOtpTokenList.pop();

  if (!id) {
    deleteOtpCookie(c);
    await rotateKek(c, kekId);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  if (encodedOtpTokenList.length > OTP_MAX_CREDENTIALS) {
    deleteOtpCookie(c);
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "");

  if (!currentOtpToken) {
    deleteOtpCookie(c);
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  /**
   * @type {string[]}
   */
  const newEncodedOtpTokenList = [];

  let expires = currentOtpToken[EXPIRES];

  const dateNow = Date.now();

  for (const encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken);
    if (!otpToken) {
      deleteOtpCookie(c);
      await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
      return c.json(ERR_OTP_INVALID_COOKIE, 400);
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES];
      }
      newEncodedOtpTokenList.push(otpToken);
    }
  }

  /**
   * It should be verified after checking if all OTP tokens are valid.
   */
  if (dateNow >= currentOtpToken[EXPIRES]) {
    return c.json(ERR_OTP_EXPIRED, 400);
  }

  if (currentOtpToken[RESEND_BLOCK] && Date.now() < currentOtpToken[RESEND_BLOCK]) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400);
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let envelope: string;

  const currentKekId = await getCurrentKekId(c);

  if (currentKekId === kekId) {
    envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH);
  } else {
    let kek: CryptoKey | undefined;
    if (currentKekId) {
      [dek, kek] = await Promise.all([createDek(), getKek(c, currentKekId)]);
    } else {
      dek = await createDek();
    }
    if (kek) {
      // @ts-expect-error: `currentKekId` must be defined if KEK exists.
      kekId = currentKekId;
      additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS);
    } else {
      additionalData = generateRandomId(KEK_ID_BYTES);
      kekId = additionalData.toBase64(BASE64URL_OPTIONS);
      kek = await createKek();
      envelope = kekId +
        new Uint8Array(
          (await Promise.all([wrapKey(dek, kek), storeKek(c, kek, kekId)]))[0]
        ).toBase64(BASE64URL_OPTIONS);
    }
  }

  if (!(await verifyOtpTokenId(c, id, expires))) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  currentOtpToken[OTP] = generateOtp();

  if (!await sendOtp(c, currentOtpToken[CREDENTIAL], currentOtpToken[OTP])) {
    /**
     * Block the OTP token.
     */
    blockOtpToken(currentOtpToken);
  } else if (OTP_ALLOW_ONLY_ONE_RESENDING) {
    currentOtpToken[RESEND_BLOCK] = undefined;
  } else {
    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS;
    /**
     * Only set resend block if the OTP token will expire in more than 4 seconds.
     */
    if ((currentOtpToken[EXPIRES] - resendBlock) > 4000) {
      currentOtpToken[RESEND_BLOCK] = resendBlock;
    }
  }

  currentOtpToken[EXPIRES] = await updateOtpTokenExpires(c, id, expires);

  if (!currentOtpToken[EXPIRES]) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_CONFLICT, 400);
  }

  encodedOtpTokenList.push(encodeOtpToken(currentOtpToken), id);

  const currentOtpTokenData = getOtpTokenData(currentOtpToken);

  setOtpCookie(
    c,
    envelope +
      await encryptTextSymmetrically(
        dek,
        encodedOtpTokenList.join(OTP_TOKEN_SEPARATOR),
        additionalData
      ),
    currentOtpTokenData.expires
  );

  return currentOtpTokenData.blocked ? c.json(ERR_CREDENTIAL_INVALID, 400) : c.json(currentOtpTokenData);
});

app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async (c) => {
  const otpData = getCookie(c, getOtpCookieName(c))?.trim();

  if (!otpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH);

  let dek = await getDek(c, kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH));

  if (!dek) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  let additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);

  const encodedOtpTokenList = await getOtpTokenList(
    dek,
    otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH),
    additionalData
  );

  if (!encodedOtpTokenList) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  const id = encodedOtpTokenList.pop();

  if (!id) {
    deleteOtpCookie(c);
    await rotateKek(c, kekId);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  if (encodedOtpTokenList.length > OTP_MAX_CREDENTIALS) {
    deleteOtpCookie(c);
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "");

  if (!currentOtpToken) {
    deleteOtpCookie(c);
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  /**
   * @type {string[]}
   */
  const newEncodedOtpTokenList = [];

  let expires = currentOtpToken[EXPIRES];

  const dateNow = Date.now();

  for (const encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken);
    if (!otpToken) {
      deleteOtpCookie(c);
      await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)]);
      return c.json(ERR_OTP_INVALID_COOKIE, 400);
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES];
      }
      newEncodedOtpTokenList.push(encodeOtpToken(otpToken));
    }
  }

  /**
   * It should be verified after checking if all OTP tokens are valid.
   */
  if (dateNow >= currentOtpToken[EXPIRES]) {
    return c.json(ERR_OTP_EXPIRED, 400);
  }

  if (
    !currentOtpToken[ATTEMPTS] ||
    (currentOtpToken[OTP_BLOCK] && currentOtpToken[OTP_BLOCK] > dateNow)
  ) {
    return c.json(ERR_OTP_VERIFICATION_NOT_ALLOWED, 403);
  }

  currentOtpToken[OTP_BLOCK] = undefined;

  if (currentOtpToken[OTP] === c.req.valid("form")) {
    /**
     * VERIFIED
     */
    if (!(await verifyOtpTokenId(c, id, expires))) {
      deleteOtpCookie(c);
      return c.json(ERR_OTP_INVALID_COOKIE, 400);
    }

    const honoRes = await finalAction(c, currentOtpToken[CREDENTIAL]);

    deleteOtpCookie(c);

    try {
      await deleteOtpTokenId(c, id, expires);
    } catch (error) {
      console.error(error);
    }

    return honoRes;
  }

  /**
   * Current KEK is retrieved before `updateOtpTokenExpires` because generating and wrapping keys takes some time.
   * And `updateOtpTokenExpires` must be executed as far in the end as possible to retrieve the newest `expires` time.
   */

  /**
   * Kek ID + Wrapped DEK.
   */
  let envelope: string;

  const currentKekId = await getCurrentKekId(c);

  if (currentKekId === kekId) {
    envelope = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH);
  } else {
    let kek: CryptoKey | undefined;
    if (currentKekId) {
      [dek, kek] = await Promise.all([createDek(), getKek(c, currentKekId)]);
    } else {
      dek = await createDek();
    }
    if (kek) {
      // @ts-expect-error: `currentKekId` must be defined if KEK exists.
      kekId = currentKekId;
      additionalData = Uint8Array.fromBase64(kekId, BASE64URL_OPTIONS);
      envelope = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS);
    } else {
      additionalData = generateRandomId(KEK_ID_BYTES);
      kekId = additionalData.toBase64(BASE64URL_OPTIONS);
      kek = await createKek();
      envelope = kekId +
        new Uint8Array(
          (await Promise.all([wrapKey(dek, kek), storeKek(c, kek, kekId)]))[0]
        ).toBase64(BASE64URL_OPTIONS);
    }
  }

  /**
   * `id` is set after envelope in case the first one fails.
   */

  const newId = await replaceOtpTokenId(c, id, expires);

  if (!newId) {
    deleteOtpCookie(c);
    return c.json(ERR_OTP_INVALID_COOKIE, 400);
  }

  currentOtpToken[ATTEMPTS]--;

  if (!currentOtpToken[ATTEMPTS]) {
    blockOtpToken(currentOtpToken);
  } else if (OTP_INVALID_BLOCK_MS && currentOtpToken[ATTEMPTS] <= OTP_ATTEMPTS_BLOCK) {
    currentOtpToken[OTP_BLOCK] = Date.now() + OTP_INVALID_BLOCK_MS;
    /**
     * If the OTP block time is greater than or similar to the OTP expiration time, block the OTP.
     */
    if ((currentOtpToken[EXPIRES] - currentOtpToken[OTP_BLOCK]) <= 1000) {
      blockOtpToken(currentOtpToken);
    }
  }

  encodedOtpTokenList.push(
    encodeOtpToken(currentOtpToken),
    newId
  );

  setOtpCookie(
    c,
    envelope +
      await encryptTextSymmetrically(
        dek,
        encodedOtpTokenList.join(OTP_TOKEN_SEPARATOR),
        additionalData
      ),
    new Date(getReducedTimePrecision(expires))
  );

  const currentOtpTokenData = getOtpTokenData(currentOtpToken);

  if (currentOtpTokenData.blocked) {
    return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 403);
  }

  if (currentOtpTokenData.otpBlock) {
    return c.json({
      ...ERR_OTP_INCORRECT,
      otpBlock: currentOtpTokenData.otpBlock
    }, 403);
  }

  return c.json(ERR_OTP_INCORRECT, 403);
});

export default app;
