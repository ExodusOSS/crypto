'use strict'

const { assertHash, P2SH_OP_0 } = require('./utils/assertHash.js')
const { toUint8Arr, toWebCryptoDigestType } = require('./utils/browserHashTools.js')
const { fromArrayBuffer } = require('./utils/output.js')
const { hashSync } = require('./hash.native.js')

const crypto = globalThis.crypto

async function hash(type, data, form) {
  assertHash(type, data, form)
  if (type === 'hash160') return hashSync('ripemd160', await hash('sha256', data), form)
  if (type === 'p2sh-hash160') {
    return hash('hash160', [P2SH_OP_0, await hash('hash160', data)], form)
  }
  const algo = toWebCryptoDigestType(type)
  if (!algo) return hashSync(type, data, form)
  const result = await crypto.subtle.digest(algo, toUint8Arr(data))
  return fromArrayBuffer(result, form)
}

module.exports = { hash, hashSync }
