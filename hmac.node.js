'use strict'

const crypto = require('crypto')
if (!crypto.webcrypto) throw new Error('Unexpected crypto-browserify or old Node.js crypto')

const { assertHmac } = require('./utils/assertHmac.js')
const { fromHash } = require('./utils/output.js')

function hmacSync(type, secret, data, form) {
  assertHmac(type, secret, data, form)
  const state = crypto.createHmac(type, secret)
  if (Array.isArray(data)) {
    for (const entry of data) state.update(entry)
  } else {
    state.update(data)
  }
  return fromHash(state, form)
}

async function hmac(type, secret, data, form) {
  return hmacSync(type, secret, data, form)
}

module.exports = { hmac, hmacSync }
