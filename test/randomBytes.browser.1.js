'use strict'

const tape = require('@exodus/test/tape')

const { getRandomValues: ignored, ...webcrypto } = require('crypto').webcrypto
delete globalThis.crypto
globalThis.crypto = webcrypto

tape('randomBytes.browser throws without crypto.getRandomValues', (t) => {
  t.ok(ignored)
  t.ok(!globalThis.crypto.getRandomValues)

  const { randomBytes } = require('../randomBytes.browser.js')

  t.throws(() => randomBytes(10), /not a function/)

  t.end()
})
