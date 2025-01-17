'use strict'

const { assertHash, P2SH_OP_0 } = require('./utils/assertHash.js')
const { hash: hashNoble } = require('./utils/hash.noble.js')
const { fromUint8Array } = require('./utils/output.js')

function hashSync(type, data, form) {
  assertHash(type, data, form)
  if (type === 'hash160') return hashSync('ripemd160', hashSync('sha256', data), form)
  if (type === 'p2sh-hash160') {
    return hashSync('hash160', [P2SH_OP_0, hashSync('hash160', data)], form)
  }
  if (Array.isArray(data)) {
    const state = hashNoble(type).create()
    for (const entry of data) state.update(entry)
    return fromUint8Array(state.digest(), form)
  }
  const result = hashNoble(type)(data)
  return fromUint8Array(result, form)
}

async function hash(type, data, form) {
  return hashSync(type, data, form)
}

module.exports = { hash, hashSync }
