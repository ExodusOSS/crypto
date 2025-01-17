'use strict'

const tape = require('@exodus/test/tape')

delete globalThis.crypto

tape('randomBytes.native throws without global crypto', (t) => {
  const { randomBytes } = require('../randomBytes.native.js')

  t.throws(() => randomBytes(10))

  t.end()
})
