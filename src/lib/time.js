/**
 * Reduces the precission of a date (milliseconds elapsed since the epoch) value to offer protection against timing attacks and fingerprinting.
 * 
 */
export function getReducedTimePrecision(time = Date.now(), precision = 1000) {
  return Math.floor(time / precision) * precision
}