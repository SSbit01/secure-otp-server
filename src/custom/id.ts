/**
 * This server generates OTP token IDs, and it needs to store them somewhere.
 * This file defines functions for storing IDs.
 * 
 * Therefore, a simple in-memory implementation has been defined using a JavaScript Array.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist IDs, so all IDs will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening.
 * - Redis, DynamoDB or similar are the best alternatives.
 */

import { OTP_MAX_AGE_MS } from "@/lib/computed"

import type { Context } from "hono"


interface IdData {
  id: number
  /**
   * Expiration time in milliseconds since epoch.
   */
  expires: number
}

const idStorage: Array<number | undefined> = []


/**
 * Stores an encryption key with the given ID and expiration time.
 * 
 * If the key could not be saved due to a technical error, an error should be thrown.
 * 
 * @async
 * @function createOtpTokenId
 * @param {Context} c - Hono context.
 * @return {Promise<IdData>} The new ID and the expiration date.
 */
export async function createOtpTokenId(c: Context): Promise<IdData> {

  // Manually clean up expired IDs, as this implementation cannot automatically delete them.
  
  let newId
  let lastValidId = -1

  const dateNow = Date.now()

  for (let i = 0; i < idStorage.length; i++) {
    const currentExpires = idStorage[i]
    if (currentExpires) {
      if (currentExpires > dateNow) {
        lastValidId = i
      } else if (newId === undefined) {
        newId = i
      } else {
        delete idStorage[i]
      }
    } else {
      newId ??= i
    }
  }

  idStorage.length = lastValidId + 1

  newId ??= idStorage.length

  const expires = dateNow + OTP_MAX_AGE_MS

  idStorage[newId] = expires

  return {
    id: newId,
    expires
  }

}


/**
 * Deletes an encryption key by its ID.
 * 
 * It is used in a "fire and forget" manner.
 * 
 * @async
 * @function deleteOtpTokenId
 * @param {Context} c - Hono context.
 * @param {IdData["id"]} id - The ID to delete.
 * @param {number} expires - Expiration time in milliseconds since epoch. It may be used to verify the ID.
 * @returns {Promise<boolean>} If delete was successful.
 */
export async function deleteOtpTokenId(c: Context, id: IdData["id"], expires: number): Promise<boolean> {

  let lastValidId = -1

  const dateNow = Date.now()

  for (let i = 0; i < idStorage.length; i++) {
    const currentExpires = idStorage[i]
    if (currentExpires) {
      if (currentExpires > dateNow) {
        lastValidId = i
      } else {
        delete idStorage[i]
      }
    }
  }

  const storedExpires = idStorage[id]

  if (!storedExpires || storedExpires !== expires) {
    idStorage.length = lastValidId + 1
    return false
  }

  if (id == lastValidId) {
    idStorage.length = lastValidId
  } else {
    delete idStorage[id]
    idStorage.length = lastValidId + 1
  }

  return true

}


/**
 * Replaces ID.
 * 
 * @async
 * @function replaceOtpTokenId
 * @param {Context} c - Hono context.
 * @param {IdData["id"]} oldId - The ID to delete.
 * @param {number} expires - Expiration time in milliseconds since epoch. It may be used to verify the ID.
 * @returns {Promise<Id|null|undefined>} New Id.
 */
export async function replaceOtpTokenId(c: Context, oldId: IdData["id"], expires: number): Promise<IdData["id"] | null | undefined> {
  
  if (idStorage[oldId] !== expires) {
    return
  }

  let newId
  let lastValidId = oldId

  const dateNow = Date.now()

  for (let i = oldId + 1; i < idStorage.length; i++) {
    const expires = idStorage[i]
    if (expires) {
      if (expires > dateNow) {
        lastValidId = i
      } else if (newId === undefined) {
        newId = i
      } else {
        delete idStorage[i]
      }
    } else {
      newId ??= i
    }
  }

  idStorage.length = lastValidId + 1

  newId ??= idStorage.length

  idStorage[newId] = expires

  return newId

}


/**
 * Updates expires date.
 * 
 * @async
 * @function updateOtpTokenExpires
 * @param {Context} c - Hono context.
 * @param {IdData["id"]} id - The ID.
 * @param {number} oldExpires - Expiration time in milliseconds since epoch. It may be used to verify the ID. It is not checked because the server already filters expired IDs.
 * @returns {Promise<number>} New expiration time.
 */
export async function updateOtpTokenExpires(c: Context, id: IdData["id"], oldExpires: number): Promise<number> {

  if (idStorage[id] !== oldExpires) {
    return 0
  }

  const newExpires = Date.now() + OTP_MAX_AGE_MS

  idStorage[id] = newExpires

  return newExpires

}