'use strict'

const tape = require('@exodus/test/tape')

const { webcrypto } = require('crypto')
delete globalThis.crypto
globalThis.crypto = { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) }

tape('randomUUID.native does not throw if crypto.getRandomValues is polyfilled', (t) => {
  const { randomUUID } = require('../randomUUID.native.js')

  t.doesNotThrow(() => randomUUID())

  t.end()
})
