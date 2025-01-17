'use strict'

const tape = require('@exodus/test/tape')

const { checkUUIDs } = require('./util/uuid.js')

tape('randomUUID.node returns correct UUIDs', (t) => {
  t.doesNotThrow(() => {
    const { randomUUID } = require('../randomUUID.node.js')
    const { valid, unique } = checkUUIDs(randomUUID)
    t.ok(valid, 'valid')
    t.ok(unique, 'unique')
  })

  t.end()
})
