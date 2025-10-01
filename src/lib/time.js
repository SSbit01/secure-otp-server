/**
 * Reduces the precission of a time value (milliseconds elapsed since the epoch) to offer protection against timing attacks and fingerprinting.
 * 
 * @param {number} [time] - The time value in milliseconds to reduce precision for. Defaults to the current time.
 * @param {number} [precision=1000] - The precision in milliseconds to which the time value should be reduced. Defaults to 1000 ms (1 second).
 */
export default function getReducedTimePrecision(time = Date.now(), precision = 1000) {

  return Math.floor(time / precision) * precision
  
}