'use strict'

const tape = require('@exodus/test/tape')

const { baseline, known, compare } = require('./util/hash.js')

tape('hash.node: hash usage', async (t) => {
  const { hash } = require('../hash.node.js')
  await baseline(t, hash)
  t.end()
})

tape('hash.node: known pairs', async (t) => {
  const { hash } = require('../hash.node.js')
  await known(t, hash)
  t.end()
})

tape('hash.node: async matches sync', async (t) => {
  const { hash, hashSync } = require('../hash.node.js')
  await compare(t, hashSync, hash)
  t.end()
})
