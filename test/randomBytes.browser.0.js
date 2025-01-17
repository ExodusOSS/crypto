'use strict'

const tape = require('@exodus/test/tape')

delete globalThis.crypto

tape('randomBytes.browser throws without global crypto', (t) => {
  const { randomBytes } = require('../randomBytes.browser.js')

  t.throws(() => randomBytes(10))

  t.end()
})
