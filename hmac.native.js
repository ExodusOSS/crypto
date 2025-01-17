'use strict'

const { assertHmac } = require('./utils/assertHmac.js')
const { hash: hashNoble } = require('./utils/hash.noble.js')
const { fromUint8Array } = require('./utils/output.js')
const { hmac: hmacNoble } = require('@noble/hashes/hmac')

function hmacSync(type, secret, data, form) {
  assertHmac(type, secret, data, form)
  if (Array.isArray(data)) {
    const state = hmacNoble.create(hashNoble(type), secret)
    for (const entry of data) state.update(entry)
    return fromUint8Array(state.digest(), form)
  }
  const result = hmacNoble(hashNoble(type), secret, data)
  return fromUint8Array(result, form)
}

async function hmac(type, secret, data, form) {
  return hmacSync(type, secret, data, form)
}

module.exports = { hmac, hmacSync }
