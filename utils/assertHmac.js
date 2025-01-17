'use strict'

const { assertHash, SUPPORTED_HMAC } = require('./assertHash.js')

function assertHmac(type, secret, arg, form) {
  assertHash(type, arg, form, SUPPORTED_HMAC)

  // This also covers Buffer as they are Uint8Array instances
  if (!(typeof secret === 'string' || secret instanceof Uint8Array)) {
    throw new Error('Unsupported hmac argument')
  }

  if (!(secret.length > 0)) {
    throw new Error('Zero-length key is not supported')
  }
}

module.exports = { assertHmac }
