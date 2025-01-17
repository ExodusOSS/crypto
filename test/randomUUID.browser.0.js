'use strict'

const tape = require('@exodus/test/tape')

delete globalThis.crypto

tape('randomUUID.browser throws without global crypto', (t) => {
  t.throws(() => require('../randomUUID.browser.js'))

  t.end()
})
