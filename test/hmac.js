'use strict'

const tape = require('@exodus/test/tape')

// TODO: mock other environments

tape('hmac === hmac.node', (t) => {
  t.strictEqual(require('../hmac.js'), require('../hmac.node.js'))
  t.end()
})
