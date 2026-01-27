/**
 * This server generates OTP token IDs, and it needs to store them somewhere.
 * This file defines functions for storing IDs.
 * 
 * Therefore, a simple in-memory implementation has been defined using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist IDs, so all IDs will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening.
 * - Redis, DynamoDB or similar are the best alternatives.
 */

import { OTP_MAX_AGE_MS } from "@/lib/computed"
import { createRandomIdString } from "@/lib/crypto/id"

import type { Context } from "hono"


const ID_BYTES = 18

const idStorage = new Map<string, number>()


/**
 * Stores an encryption key with the given ID and expiration time.
 * 
 * If the key could not be saved due to a technical error, an error should be thrown.
 * 
 * @async
 * @function createOtpTokenListId
 * @param {Context} c - Hono context.
 * @return {Promise<[string, number]>} The new ID and the expiration date.
 */
export async function createOtpTokenListId(c: Context): Promise<[string, number]> {

  // Manually clean up expired IDs, as this implementation cannot automatically delete them.

  const dateNow = Date.now()

  for (const [id, expires] of idStorage) {
    if (expires <= dateNow) {
      idStorage.delete(id)
    }
  }

  const newId = createRandomIdString(ID_BYTES)
  const expires = dateNow + OTP_MAX_AGE_MS

  idStorage.set(newId, expires)

  return [newId, expires]

}


/**
 * Deletes an encryption key by its ID.
 * 
 * @async
 * @function deleteOtpTokenId
 * @param {Context} c - Hono context.
 * @param {string} id - The ID to delete.
 * @param {number} [expires] - Expiration time in milliseconds since epoch used to verify the ID; if not provided, the ID must be deleted without verification.
 * @returns {Promise<boolean>} If delete was successful.
 */
export async function deleteOtpTokenId(c: Context, id: string, expires?: number): Promise<boolean> {

  if (!expires) {
    return idStorage.delete(id)
  }

  const storedExpires = idStorage.get(id)

  if (!storedExpires) {
    return false
  }

  if (storedExpires !== expires) {
    if (storedExpires <= Date.now()) {
      idStorage.delete(id)
    }
    return false
  }

  return idStorage.delete(id)

}


/**
 * Replaces ID.
 * 
 * @async
 * @function replaceOtpTokenId
 * @param {Context} c - Hono context.
 * @param {string} oldId - The ID to delete.
 * @param {number} expires - Expiration time in milliseconds since epoch. It may be used to verify the ID.
 * @returns {Promise<string|undefined>} New Id.
 */
export async function replaceOtpTokenId(c: Context, oldId: string, expires: number): Promise<string | undefined> {
  
  if (idStorage.get(oldId) !== expires) {
    return
  }

  // Manually clean up expired IDs, as this implementation cannot automatically delete them.

  const dateNow = Date.now()

  for (const [id, expires] of idStorage) {
    if (expires <= dateNow) {
      idStorage.delete(id)
    }
  }

  idStorage.delete(oldId)

  const newId = createRandomIdString(ID_BYTES)

  idStorage.set(newId, expires)

  return newId

}


/**
 * Updates expires date.
 * 
 * @async
 * @function updateOtpTokenExpires
 * @param {Context} c - Hono context.
 * @param {string} id - The ID.
 * @param {number} oldExpires - Expiration time in milliseconds since epoch. It may be used to verify the ID. It is not checked because the server already filters expired IDs.
 * @returns {Promise<number>} New expiration time.
 */
export async function updateOtpTokenExpires(c: Context, id: string, oldExpires: number): Promise<number> {

  if (idStorage.get(id) !== oldExpires) {
    return 0
  }

  const newExpires = Date.now() + OTP_MAX_AGE_MS

  idStorage.set(id, newExpires)

  return newExpires

}