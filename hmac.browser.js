'use strict'

const { assertHmac } = require('./utils/assertHmac.js')
const { toUint8Arr, toWebCryptoDigestType } = require('./utils/browserHashTools.js')
const { fromArrayBuffer } = require('./utils/output.js')
const { hmacSync } = require('./hmac.native.js')

const crypto = globalThis.crypto

async function hmac(type, secret, data, form) {
  assertHmac(type, secret, data, form)
  const hashAlgo = toWebCryptoDigestType(type)
  if (!hashAlgo) return hmacSync(type, secret, data, form)
  const algo = { name: 'HMAC', hash: hashAlgo }
  const key = await crypto.subtle.importKey('raw', toUint8Arr(secret), algo, false, ['sign'])
  const result = await crypto.subtle.sign(algo, key, toUint8Arr(data))
  return fromArrayBuffer(result, form)
}

module.exports = { hmac, hmacSync }
