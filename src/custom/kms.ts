/**
 * This server generates Key Encryption Keys (KEKs) with their IDs, and it needs to store them somewhere.
 * This file defines functions for storing KEKs.
 * 
 * Therefore, a simple in-memory KMS implementation has been defined using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist KEKs, so all KEKs will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g. multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening.
 * - Redis, DynamoDB or similar are the best alternatives.
 * 
 * A custom key rotation implementation with envelope encryption with a specialized KMS is recommended.
 */

import { OTP_MAX_AGE_MS } from "@/lib/computed"

import type { Context } from "hono"


/// CUSTOM
type KeyData = [expires: number, rotate: number, key: CryptoKey]


const ROTATE_TIME = process.env.NODE_ENV === "test"
  ? 5
  : 7776000000  // 90 days in miliseconds.

const keyStorage = new Map<string, KeyData>()
///


/**
 * Deletes KEK.
 * 
 * @async
 * @function deleteKek
 * @param {Context} c - Hono context.
 * @param {string} id - The ID of the KEK to delete.
 */
export async function deleteKek(c: Context, id: string) {

  console.warn("DELETING KEK: " + id)

  keyStorage.delete(id)
  
}


/**
 * Retrieves current KEK ID.
 * 
 * @async
 * @function getCurrentKekId
 * @param {Context} c - Hono context.
 * @return {Promise<string|undefined>} A promise that resolves to the key ID if found, otherwise `undefined`.
 */
export async function getCurrentKekId(c: Context): Promise<string | undefined> {

  // Manually clean up expired keys, as this implementation cannot automatically delete them.

  let currentKeyEntry: [string, KeyData] | undefined

  const dateNow = Date.now()

  for (const keyEntry of keyStorage) {
    const expires = keyEntry[1][0]
    if (expires <= dateNow) {
      keyStorage.delete(keyEntry[0])
    } else if (!currentKeyEntry || expires < currentKeyEntry[1][0]) {
      currentKeyEntry = keyEntry
    }
  }


  if (
    !currentKeyEntry ||
    // Checking rotation date.
    currentKeyEntry[1][1] <= dateNow
  ) {
    return
  }

  return currentKeyEntry[0]

}


/**
 * Retrieves an encryption key by its ID.
 * 
 * @async
 * @function getKek
 * @param {Context} c - Hono context.
 * @param {string} keyId - The ID of the encryption key to retrieve.
 * @return {Promise<CryptoKey|undefined>} A promise that resolves to the `CryptoKey` if found, otherwise `undefined`.
 */
export async function getKek(c: Context, keyId: string): Promise<CryptoKey | undefined> {

  const keyData = keyStorage.get(keyId)

  if (!keyData) {
    return
  }

  if (keyData[0] <= Date.now()) {
    keyStorage.delete(keyId)
    return
  }

  return keyData[2]

}


/**
 * Stores an encryption key with the given ID and expiration time.
 * 
 * If the key could not be saved due to a technical error, an error should be thrown.
 * 
 * @async
 * @function storeKek
 * @param {Context} c - Hono context.
 * @param {CryptoKey} key - The encryption key to store.
 * @param {string} id - ID of the key, store it too.
 * @return {Promise<boolean>} A boolean indicating whether the operation was successful.
 */
export async function storeKek(c: Context, key: CryptoKey, id: string): Promise<boolean> {

  const rotate = Date.now() + ROTATE_TIME
  
  keyStorage.set(id, [rotate + OTP_MAX_AGE_MS, rotate, key])

  return true

}