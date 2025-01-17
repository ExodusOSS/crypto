'use strict'

const tape = require('@exodus/test/tape')

const { webcrypto } = require('crypto')
delete globalThis.crypto
globalThis.crypto = { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) }

tape('randomBytes.native does not throw if crypto.getRandomValues is polyfilled', (t) => {
  const { randomBytes } = require('../randomBytes.native.js')

  t.doesNotThrow(() => {
    const rand = randomBytes(20)
    t.ok(Buffer.isBuffer(rand), 'returns a Buffer instance')
    t.strictEqual(rand.length, 20, 'length is correct')
  })

  t.end()
})
