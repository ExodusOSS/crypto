'use strict'

const SUPPORTED_HMAC = [
  ...['sha256', 'sha384', 'sha512', 'sha512-256'], // SHA-2
  ...['sha3-256', 'sha3-384', 'sha3-512'], // SHA-3
  'ripemd160',
]

const SUPPORTED_HASH = [...SUPPORTED_HMAC, 'hash160', 'p2sh-hash160']

// 'supported' argument is used by assertHmac() which all hmac methods use
function assertHash(type, arg, form, supported = SUPPORTED_HASH) {
  // NOTE: this has to be in sync with other places where type is used
  if (!supported.includes(type)) {
    throw new Error('Unsupported hash type')
  }

  // This also covers Buffer as they are Uint8Array instances
  if (!(typeof arg === 'string' || arg instanceof Uint8Array)) {
    if (Array.isArray(arg)) {
      // Allow hashing an non-empty array of Uint8Array instances or Buffer instances
      if (!(arg.length > 0)) throw new Error('An array in hash argument must not be empty')
      for (const x of arg) {
        if (x instanceof Uint8Array) continue
        throw new Error('Unsupported entry in hash argument')
      }
    } else {
      throw new Error('Unsupported hash argument')
    }
  }

  if (![undefined, 'hex', 'buffer', 'uint8'].includes(form)) {
    throw new Error('Unsupported hash format')
  }
}

const P2SH_OP_0 = Buffer.from('0014', 'hex')

module.exports = { assertHash, SUPPORTED_HMAC, SUPPORTED_HASH, P2SH_OP_0 }
