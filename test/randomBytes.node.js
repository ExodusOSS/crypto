'use strict'

const tape = require('@exodus/test/tape')

tape('randomBytes.node works without global crypto', (t) => {
  const { randomBytes } = require('../randomBytes.node.js')

  t.doesNotThrow(() => {
    const rand = randomBytes(10)
    t.ok(Buffer.isBuffer(rand), 'returns a Buffer instance')
    t.strictEqual(rand.length, 10, 'length is correct')
  })

  t.end()
})
