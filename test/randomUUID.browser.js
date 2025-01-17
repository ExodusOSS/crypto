'use strict'

const tape = require('@exodus/test/tape')

const { checkUUIDs } = require('./util/uuid.js')

if (!globalThis.crypto) globalThis.crypto = require('crypto').webcrypto

tape('randomUUID.browser returns correct UUIDs', (t) => {
  t.doesNotThrow(() => {
    const { randomUUID } = require('../randomUUID.browser.js')
    const { valid, unique } = checkUUIDs(randomUUID)
    t.ok(valid, 'valid')
    t.ok(unique, 'unique')
  })

  t.end()
})

tape('randomUUID.browser does not throw if crypto is polyfilled', (t) => {
  t.doesNotThrow(() => {
    const { randomUUID } = require('../randomUUID.browser.js')
    t.doesNotThrow(() => randomUUID())
  })

  t.end()
})
