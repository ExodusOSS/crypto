'use strict'

const tape = require('@exodus/test/tape')

const { randomUUID: ignored, ...webcrypto } = require('crypto').webcrypto
delete globalThis.crypto
globalThis.crypto = webcrypto

tape('randomUUID.browser throws without crypto.randomUUID', (t) => {
  t.ok(ignored)
  t.ok(!globalThis.crypto.randomUUID)

  t.throws(() => require('../randomUUID.browser.js'))

  t.end()
})
