'use strict'

const tape = require('@exodus/test/tape')

delete globalThis.crypto

tape('randomUUID.native throws without global crypto', (t) => {
  const { randomUUID } = require('../randomUUID.native.js')

  t.throws(() => randomUUID())

  t.end()
})
