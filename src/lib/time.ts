export function getReducedTimePrecision(time = Date.now(), roundFunction = Math.trunc, precision = 1000) {
  return roundFunction(time / precision) * precision;
}

export function secondsToMs(value: number) {
  return value * 1000;
}
