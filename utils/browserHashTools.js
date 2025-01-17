'use strict'

// We need Buffer either way for digest
// Used only on input processing, so we don't care if it is of an extended type e.g Buffer
function toUint8Arr(arg) {
  if (arg instanceof Uint8Array) return arg
  if (typeof arg === 'string') return Buffer.from(arg)
  if (Array.isArray(arg)) return Buffer.concat(arg) // we accept only Uint8Array/Buffer instances in an array
  throw new Error('Unexpected arg type')
}

// this returns null on unsupported types to fall back to noble impl
function toWebCryptoDigestType(type) {
  if (type === 'sha256') return 'SHA-256'
  if (type === 'sha384') return 'SHA-384'
  if (type === 'sha512') return 'SHA-512'
  if (type === 'ripemd160' || type === 'sha512-256') return null
  if (type === 'sha3-256' || type === 'sha3-384' || type === 'sha3-512') {
    // TODO: enable this when https://twiss.github.io/webcrypto-modern-algos/ lands (sha3 / supports)
    /*
    if (!globalThis.crypto?.supports) return null
    const upper = type.toUpperCase()
    return globalThis.crypto.supports('digest', upper) ? upper : null
    */
    return null
  }
  throw new Error('Unexpected hash type')
}

module.exports = { toUint8Arr, toWebCryptoDigestType }
