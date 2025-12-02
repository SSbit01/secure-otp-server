/**
 * This server generates keys with their IDs constantly, and it needs to store them somewhere.
 * This file defines functions for storing keys.
 * 
 * Therefore, a simple in-memory KMS implementation has been defined using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist keys, so all keys will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening.
 * - Redis, DynamoDB or similar are the best alternatives.
 * 
 * A custom key rotation implementation with envelope encryption with a specialized KMS is recommended.
 */

import { OTP_MAX_AGE_MS } from "@/lib/computed"
import { createRandomId } from "@/lib/crypto/id"

import type { Context } from "hono"


interface CurrentKey {
  id: string | number
  key: CryptoKey
}


/// CUSTOM
type KeyData = [expires: number, rotate: number, key: CryptoKey, uses?: number]


const ROTATE_TIME = 2592000000  // 30 days in miliseconds.
const ROTATE_USES = 1000000000  // 1 billion.

const keyStorage = new Map<CurrentKey["id"], KeyData>()
///


/**
 * Retrieves an encryption key by its ID.
 * 
 * @async
 * @function getCurrentKey
 * @param {Context} c - Hono context.
 * @return {Promise<CurrentKey|undefined>} A promise that resolves to the `CurrentKey` if found, otherwise `undefined`.
 */
export async function getCurrentKey(c: Context): Promise<CurrentKey | undefined> {

  // Manually clean up expired keys, as this implementation cannot automatically delete them.

  let currentKeyEntry: [string | number, KeyData] | undefined

  const dateNow = Date.now()

  for (const keyEntry of keyStorage) {
    const expires = keyEntry[1][0]
    if (expires <= dateNow) {
      keyStorage.delete(keyEntry[0])
    } else if (!currentKeyEntry || expires < currentKeyEntry[1][0]) {
      currentKeyEntry = keyEntry
    }
  }

  if (!currentKeyEntry) {
    return
  }

  const keyData = currentKeyEntry[1]

  if (keyData[1] <= dateNow || !keyData[3]) {
    return
  }

  if (keyData[3] >= ROTATE_USES) {
    /** Trim the array to save space. */
    keyData.length = 3
    return
  }

  keyData[3]++

  return {
    id: currentKeyEntry[0],
    key: keyData[2]
  }

}


/**
 * Retrieves an encryption key by its ID.
 * 
 * @async
 * @function getKey
 * @param {Context} c - Hono context.
 * @param {CurrentKey["id"]} keyId - The ID of the encryption key to retrieve.
 * @return {Promise<CryptoKey|undefined>} A promise that resolves to the `CryptoKey` if found, otherwise `undefined`.
 */
export async function getKey(c: Context, keyId: CurrentKey["id"]): Promise<CryptoKey | undefined> {

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
 * @function storeKey
 * @param {Context} c - Hono context.
 * @param {CryptoKey} key - The encryption key to store.
 * @return {Promise<CurrentKey["id"]>} The ID of the stored key.
 */
export async function storeKey(c: Context, key: CryptoKey): Promise<CurrentKey["id"]> {

  // Manually clean up expired keys, as this implementation cannot automatically delete them.
  
  const dateNow = Date.now()

  for (const [keyId, [expires]] of keyStorage) {
    if (expires <= dateNow) {
      keyStorage.delete(keyId)
    }
  }

  const rotate = dateNow + ROTATE_TIME
  const data: KeyData = [rotate + OTP_MAX_AGE_MS, rotate, key, 1]

  let id: string

  do {
    id = createRandomId()
  } while (keyStorage.has(id))

  keyStorage.set(id, data)

  return id

}