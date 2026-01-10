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
 * @param {NumberFunction} [roundFunction] - The rounding function to use (e.g., Math.trunc, Math.ceil, Math.round). Defaults to Math.trunc.
 * @param {number} [precision]
 * @returns {number} - The time value with reduced precision.
 */
export function getReducedTimePrecision(time = Date.now(), roundFunction = Math.trunc, precision = 1000) {
  return roundFunction(time / precision) * precision
}


/**
 * @function secondsToMs
 * @param {number} value 
 */
export function secondsToMs(value) {
  return value * 1000
}