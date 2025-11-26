/**
 * This server generates keys with their IDs constantly, and it needs to store them somewhere.
 * This file defines functions for storing keys.
 * 
 * Therefore, a simple in-memory KMS implementation has been defined using a JavaScript Array.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist keys, so all keys will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening.
 * - Redis, DynamoDB or similar are the best alternatives.
 * 
 * A custom key rotation implementation with envelope encryption with a specialized KMS is recommended.
 */

import { MAX_DURATION_SECONDS } from "@/custom/otp"

import type { Context } from "hono"



const ROTATE = 2592000000  // 30 days in miliseconds.



const keyStorage: Array<[key: CryptoKey, createdAt: number, encryptions: number] | undefined> = []


/**
 * Stores an encryption key with the given ID and expiration time.
 * 
 * If the key could not be saved due to a technical error, an error should be thrown.
 * 
 * @async
 * @function storeEncryptionKey
 * @param {Context} c - Hono context.
 * @param {CryptoKey} key - The encryption key to store.
 * @param {number} [dateNow] - Current date in milliseconds elapsed since the epoch.
 * @return {Promise<boolean>} A promise that resolves to `true` if the key was stored, otherwise `false`.
 */
export async function storeEncryptionKey(c: Context, key: CryptoKey, dateNow = Date.now()) {

  /**
   * Manually clean up expired keys, as this implementation cannot automatically delete them.
   */
  let newId
  let lastValidId = -1

  for (let i = 0; i < keyStorage.length; i++) {
    const createdAt = keyStorage[i]?.[1]
    if (createdAt) {
      if ((dateNow - createdAt) < dateNow) {
        lastValidId = i
      } else if (newId === undefined) {
        newId = i
      } else {
        delete keyStorage[i]
      }
    } else if (newId === undefined) {
      newId = i
    }
  }

  keyStorage.length = lastValidId + 1

  newId ??= keyStorage.length

  keyStorage[newId] = [key, dateNow, 0]

  return true

}


/**
 * Retrieves an encryption key by its ID.
 * 
 * @async
 * @function getEncryptionKey
 * @param {Context} c - Hono context.
 * @param {number} keyId - The ID of the encryption key to retrieve.
 * @return {Promise<CryptoKey|undefined>} A promise that resolves to the `CryptoKey` if found, otherwise `undefined`.
 */
export async function getEncryptionKey(c: Context, keyId: number): Promise<CryptoKey | undefined> {

  const data = keyStorage[keyId]

  if (data) {
    data[2]++
    return data[0]
  }

}


/**
 * Deletes an encryption key by its ID.
 * 
 * It is used in a "fire and forget" manner.
 * 
 * @async
 * @function deleteEncryptionKey
 * @param {Context} c - Hono context.
 * @param {string} keyId - The ID of the encryption key to delete.
 */
export async function deleteEncryptionKey(c: Context, keyId: string) {

  /**
   * Manually clean up expired keys, as this implementation cannot automatically delete them.
   */
  const date = new Date()

  for (const [id, [, expires]] of keyStorage) {
    if (date >= expires) {
      keyStorage.delete(id)
    }
  }

  return keyStorage.delete(keyId)

}