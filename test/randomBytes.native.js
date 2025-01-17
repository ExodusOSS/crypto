'use strict'

const tape = require('@exodus/test/tape')

if (!globalThis.crypto) globalThis.crypto = require('crypto').webcrypto

tape('randomBytes.native === randomBytes.browser', (t) => {
  const native = require('../randomBytes.native.js')
  const browser = require('../randomBytes.browser.js')
  t.strictEqual(native, browser)

  t.end()
})

tape('randomBytes.native does not throw if crypto is polyfilled', (t) => {
  const { randomBytes } = require('../randomBytes.native.js')

  t.doesNotThrow(() => {
    const rand = randomBytes(10)
    t.ok(Buffer.isBuffer(rand), 'returns a Buffer instance')
    t.strictEqual(rand.length, 10, 'length is correct')
  })

  t.end()
})
