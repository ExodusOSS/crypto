'use strict'

const tape = require('@exodus/test/tape')

// TODO: mock other environments

tape('randomBytes === randomBytes.node', (t) => {
  t.strictEqual(require('../randomBytes.js'), require('../randomBytes.node.js'))
  t.end()
})
