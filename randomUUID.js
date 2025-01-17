'use strict'

// Prefers Web Crypto implementation

let crypto = globalThis.crypto
if (typeof globalThis.crypto === 'undefined') {
  crypto = require('crypto')
  if (!crypto.webcrypto) throw new Error('Unexpected crypto-browserify or old Node.js crypto')
}

exports.randomUUID = crypto.randomUUID.bind(crypto)
