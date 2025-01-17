'use strict'

const tape = require('@exodus/test/tape')

const { baseline, known, compare } = require('./util/hash.js')

tape('hash.native: hash usage', async (t) => {
  const { hash } = require('../hash.native.js')
  await baseline(t, hash)
  t.end()
})

tape('hash.native: known pairs', async (t) => {
  const { hash } = require('../hash.native.js')
  await known(t, hash)
  t.end()
})

tape('hash.native: random data hash matches with hash.node', async (t) => {
  const { hash, hashSync } = require('../hash.native.js')
  const { hashSync: node } = require('../hash.node.js')
  await compare(t, node, hash, hashSync)
  t.end()
})
