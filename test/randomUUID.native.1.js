'use strict'

const tape = require('@exodus/test/tape')

const { getRandomValues: ignored, ...webcrypto } = require('crypto').webcrypto
delete globalThis.crypto
globalThis.crypto = webcrypto

tape('randomUUID.native throws without crypto.getRandomValues', (t) => {
  t.ok(ignored)
  t.ok(!globalThis.crypto.getRandomValues)

  const { randomUUID } = require('../randomUUID.native.js')

  t.throws(() => randomUUID(), /not a function/)

  t.end()
})
