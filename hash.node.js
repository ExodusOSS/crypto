'use strict'

const crypto = require('crypto')
if (!crypto.webcrypto) throw new Error('Unexpected crypto-browserify or old Node.js crypto')

const { assertHash, P2SH_OP_0 } = require('./utils/assertHash.js')
const { fromHash } = require('./utils/output.js')

function hashSync(type, data, form) {
  assertHash(type, data, form)
  if (type === 'hash160') return hashSync('ripemd160', hashSync('sha256', data), form)
  if (type === 'p2sh-hash160') {
    return hashSync('hash160', [P2SH_OP_0, hashSync('hash160', data)], form)
  }
  const state = crypto.createHash(type)
  if (Array.isArray(data)) {
    for (const entry of data) state.update(entry)
  } else {
    state.update(data)
  }
  return fromHash(state, form)
}

async function hash(type, data, form) {
  return hashSync(type, data, form)
}

module.exports = { hash, hashSync }
