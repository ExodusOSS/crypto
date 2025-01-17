export function toUint8Array(input) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') {
    if (input.length % 2 === 0 && /^[0-9a-f]*$/iu.test(input)) return Buffer.from(input, 'hex')
    throw new Error('supplied string is not in hex format')
  }
  throw new Error('expected Uint8Array, Buffer or hex string')
}
