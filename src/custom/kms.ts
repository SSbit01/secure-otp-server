/**
 * This server generates keys with their IDs constantly, and it needs to store them somewhere.
 * This file defines functions for storing keys.
 * 
 * Therefore, a simple in-memory KMS implementation has been defined using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist keys, so all keys will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening (Cloudflare Workers KV, Redis, DynamoDB or similar are the best alternatives).
 */

import { MAX_DURATION_SECONDS } from "@/custom/otp"

import type { Context } from "hono"



const keyStorage = new Map<string, [key: CryptoKey, expires: Date]>()


/**
 * Stores an encryption key with the given ID and expiration time.
 * 
 * If the key could not be saved due to a technical error, an error should be thrown.
 * 
 * @async
 * @function storeEncryptionKey
 * @param {Context} c - Hono context.
 * @param {string} keyId - The ID of the encryption key to store. Created using `/src/lib/crypto/id.js`.
 * @param {CryptoKey} key - The encryption key to store.
 * @param {Date} expires - The expiration date.
 * @return {Promise<boolean>} A promise that resolves to `true` if the key was stored, otherwise `false`.
 */
export async function storeEncryptionKey(c: Context, keyId: string, key: CryptoKey, expires: Date) {

  /**
   * Manually clean up expired keys, as this implementation cannot automatically delete them.
   */
  const date = new Date()

  for (const [id, [, expires]] of keyStorage) {
    if (date >= expires) {
      keyStorage.delete(id)
    }
  }

  keyStorage.set(keyId, [key, expires])

  return true

}


/**
 * Retrieves an encryption key by its ID.
 * 
 * @async
 * @function getEncryptionKey
 * @param {Context} c - Hono context.
 * @param {string} keyId - The ID of the encryption key to retrieve.
 * @return {Promise<CryptoKey|undefined>} A promise that resolves to the `CryptoKey` if found, otherwise `undefined`.
 */
export async function getEncryptionKey(c: Context, keyId: string): Promise<CryptoKey | undefined> {

  return keyStorage.get(keyId)?.[0]

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