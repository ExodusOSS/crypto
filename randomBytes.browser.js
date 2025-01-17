'use strict'

const { assertSize } = require('./utils/assertSize.js')

const crypto = globalThis.crypto

function randomBytes(size) {
  assertSize(size)
  const buffer = Buffer.alloc(size)
  crypto.getRandomValues(buffer)
  return buffer
}

module.exports = { randomBytes }
