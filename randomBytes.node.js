'use strict'

const crypto = require('crypto')
if (!crypto.webcrypto) throw new Error('Unexpected crypto-browserify or old Node.js crypto')

const { assertSize } = require('./utils/assertSize.js')

function randomBytes(size) {
  assertSize(size)
  return crypto.randomBytes(size)
}

module.exports = { randomBytes }
