'use strict'

const tape = require('@exodus/test/tape')

// TODO: mock other environments

tape('hash === hash.node', (t) => {
  t.strictEqual(require('../hash.js'), require('../hash.node.js'))
  t.end()
})
