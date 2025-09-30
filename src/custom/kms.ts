/**
 * A simple in-memory KMS implementation using a JavaScript Map.
 * 
 * - It is the cheapest and easiest implementation and works fine if the server is always on.
 * - This implementation does not persist keys, so all keys will be lost when the server restarts.
 * - In-memory implementations do not work well in distributed systems (e.g., multiple server instances behind a load balancer).
 * - In-memory implementations do not work well in serverless environments, because they are constantly closing and opening (Cloudflare Workers KV, Vercel KV, Redis or similar are the best alternatives).
 */

import { MAX_DURATION_SECONDS } from "@/custom/otp"
import getReducedTimePrecision from "@/lib/time"

import type { Context } from "hono"



const keyStorage = new Map<string, [key: CryptoKey, expires: number]>()



export async function doesEncryptionKeyExist(c: Context, keyID: string) {

  return keyStorage.has(keyID)

}


export async function storeEncryptionKey(c: Context, keyID: string, key: CryptoKey, expires: number) {

  /**
   * Manually clean up expired keys, as this implementation cannot automatically delete them.
   */
  const dateNow = getReducedTimePrecision()
  for (const [id, [, expires]] of keyStorage) {
    if (dateNow >= expires) {
      keyStorage.delete(id)
    }
  }

  keyStorage.set(keyID, [key, expires])

}


export async function getEncryptionKey(c: Context, keyID: string): Promise<CryptoKey | undefined> {

  return keyStorage.get(keyID)?.[0]

}


export async function deleteEncryptionKey(c: Context, keyID: string) {

  /**
   * Manually clean up expired keys, as this implementation cannot automatically delete them.
   */
  const dateNow = getReducedTimePrecision()
  for (const [id, [, expires]] of keyStorage) {
    if (dateNow >= expires) {
      keyStorage.delete(id)
    }
  }

  return keyStorage.delete(keyID)
  
}