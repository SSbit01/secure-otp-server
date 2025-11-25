/**
 * This server generates OTP token IDs, and it needs to store them somewhere.
 * This file defines functions for storing IDs.
 * 
 * Therefore, a simple in-memory KMS implementation has been defined using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist IDs, so all IDs will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening (Redis, DynamoDB or similar are the best alternatives).
 */

import { MAX_DURATION_SECONDS } from "@/custom/otp"

import type { Context } from "hono"


interface IdObject {
  id: number
  expires: number
}


const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000

const idStorage: number[] = []


/**
 * Stores an encryption key with the given ID and expiration time.
 * 
 * If the key could not be saved due to a technical error, an error should be thrown.
 * 
 * @async
 * @function createId
 * @param {Context} c - Hono context.
 * @param {number} [dateNow] - Current date in milliseconds elapsed since the epoch.
 * @return {Promise<IdObject>} The new ID and the expiration date.
 */
export async function createId(c: Context, dateNow = Date.now()): Promise<IdObject> {

  /**
   * Manually clean up expired IDs, as this implementation cannot automatically delete them.
   */
  let newId
  let lastValidId = -1

  for (let i = 0; i < idStorage.length; i++) {
    const expires = idStorage[i]
    if (expires) {
      if (dateNow < expires) {
        lastValidId = i
      } else {
        delete idStorage[i]
        if (newId === undefined) {
          newId = i
        }
      }
    } else if (newId === undefined) {
      newId = i
    }
  }

  idStorage.length = lastValidId + 1

  newId ??= idStorage.length

  const expires = dateNow + MAX_DURATION_MS

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
 * @function deleteId
 * @param {Context} c - Hono context.
 * @param {IdObject["id"]} id - The ID to delete.
 * @param {number} [dateNow] - Current date in milliseconds elapsed since the epoch.
 * @returns {boolean} If delete was successful.
 */
export async function deleteId(c: Context, id: IdObject["id"], dateNow = Date.now()) {

  let lastValidId = -1

  for (let i = 0; i < idStorage.length; i++) {
    const expires = idStorage[i]
    if (expires) {
      if (dateNow < expires) {
        lastValidId = i
      } else {
        delete idStorage[i]
      }
    }
  }

  if (!idStorage[id]) {
    idStorage.length = lastValidId + 1
    return false
  }

  if (id === lastValidId) {
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
 * @function replaceId
 * @param {Context} c - Hono context.
 * @param {IdObject["id"]} oldId - The ID to delete.
 * @param {number} expires - Expires date in milliseconds elapsed since the epoch. Used to verify the ID.
 * @param {number} [dateNow] - Current date in milliseconds elapsed since the epoch.
 * @returns {boolean} If delete was successful.
 */
export async function replaceId(c: Context, oldId: IdObject["id"], expires: number, dateNow = Date.now()) {

  if (idStorage[oldId] !== expires || expires >= dateNow) {
    return
  }

  let newId
  let lastValidId = oldId

  for (let i = oldId + 1; i < idStorage.length; i++) {
    const expires = idStorage[i]
    if (expires < dateNow) {
      lastValidId = i
    } else {
      delete idStorage[i]
      if (newId === undefined) {
        newId = i
      }
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
 * @function updateExpires
 * @param {Context} c - Hono context.
 * @param {IdObject["id"]} id - The ID.
 * @param {number} oldExpires - Old expires date in milliseconds elapsed since the epoch. Used to verify the ID.
 * @param {number} [dateNow] - Current date in milliseconds elapsed since the epoch.
 * @returns {boolean} If delete was successful.
 */
export async function updateExpires(c: Context, id: IdObject["id"], oldExpires: number, dateNow = Date.now()) {

  if (idStorage[id] !== oldExpires || oldExpires >= dateNow) {
    return
  }

  const expires = dateNow + MAX_DURATION_MS

  idStorage[id] = expires

  return expires

}