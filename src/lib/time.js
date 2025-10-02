import { MINIMUM_DELAY_BETWEEN_VERIFICATIONS_MS } from "@/custom/otp"


/**
 * Checks if the time elapsed since the provided time is less than the minimum delay between verifications.
 * 
 * @function isLessThanDelay
 * @param {number} time
 * @param {number} [dateNow]
 * @param {number} [delay]
 */
export function isLessThanDelay(time, dateNow = Date.now(), delay = MINIMUM_DELAY_BETWEEN_VERIFICATIONS_MS) {

  return (dateNow - time) < delay
  
}


/**
 * Reduces the precission of a time value (milliseconds elapsed since the epoch) to offer protection against timing attacks and fingerprinting.
 * 
 * @function getReducedTimePrecision
 * @param {number} [time] - The time value in milliseconds to reduce precision for. Defaults to the current time.
 * @param {number} [precision=1000] - The precision in milliseconds to which the time value should be reduced. Defaults to 1000 ms (1 second).
 * @returns {number} - The time value with reduced precision.
 */
export function getReducedTimePrecision(time = Date.now(), precision = 1000) {

  return Math.floor(time / precision) * precision
  
}