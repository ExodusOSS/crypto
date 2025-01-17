'use strict'

const tape = require('@exodus/test/tape')

const { mockSingularFunctionBind } = require('./util/setup.js')

// TODO: mock other environments

delete globalThis.crypto
mockSingularFunctionBind()

tape('randomUUID === randomUUID.node without global crypto', (t) => {
  const { randomUUID: generic } = require('../randomUUID.js')
  const { randomUUID: node } = require('../randomUUID.node.js')
  t.ok(generic.source && generic.args, 'bind generic')
  t.ok(node.source && node.args, 'bind node')
  t.strictEqual(node.source, generic.source, 'sources are equal')
  t.deepEqual(node.args, generic.args, 'args are equal')
  t.end()
})
