'use strict'

const tape = require('@exodus/test/tape')

const { webcrypto } = require('crypto')
delete globalThis.crypto
globalThis.crypto = { randomUUID: webcrypto.randomUUID.bind(webcrypto) }

tape('randomUUID.browser does not throw if crypto.randomUUID is polyfilled', (t) => {
  t.doesNotThrow(() => {
    const { randomUUID } = require('../randomUUID.browser.js')
    t.doesNotThrow(() => randomUUID())
  })

  t.end()
})
