import { MINIMUM_DELAY_BETWEEN_REQUESTS_MS } from "@/custom/otp"


/**
 * @callback NumberFunction
 * @param {number} x
 * @returns {number}
 */


/**
 * Reduces the precission of a time value (milliseconds elapsed since the epoch) to offer protection against timing attacks and fingerprinting.
 * 
 * @function getReducedTimePrecision
 * @param {number} [time] - The time value in milliseconds to reduce precision for. Defaults to the current time.
 * @param {NumberFunction} [roundFunction] - The rounding function to use (e.g., Math.floor, Math.ceil, Math.round). Defaults to Math.floor.
 * @param {number} [precision]
 * @returns {number} - The time value with reduced precision.
 */
export function getReducedTimePrecision(time = Date.now(), roundFunction = Math.floor, precision = 1000) {
  return roundFunction(time / precision) * precision
}


/**
 * Checks if the time elapsed since the provided time is less than the minimum delay between verifications.
 * 
 * @function isWithinDelay
 * @param {number} time
 * @param {number} [delay]
 * @param {number} [dateNow]
 * @returns {boolean}
 */
export function isWithinDelay(time, delay = MINIMUM_DELAY_BETWEEN_REQUESTS_MS, dateNow = Date.now()) {
  return (dateNow - time) < delay
}


/**
 * @function secondsToMs
 * @param {number} value 
 */
export function secondsToMs(value) {
  return value * 1000
}