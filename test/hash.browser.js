'use strict'

const tape = require('@exodus/test/tape')

const { baseline, known, compare } = require('./util/hash.js')

if (!globalThis.crypto) globalThis.crypto = require('crypto').webcrypto

tape('hash.browser: hash usage', async (t) => {
  const { hash } = require('../hash.browser.js')
  await baseline(t, hash)
  t.end()
})

tape('hash.browser: known pairs', async (t) => {
  const { hash } = require('../hash.browser.js')
  await known(t, hash)
  t.end()
})

tape('hash.browser: random data hash matches with hash.node', async (t) => {
  const { hash, hashSync } = require('../hash.native.js')
  const { hashSync: node } = require('../hash.node.js')
  await compare(t, node, hash, hashSync)
  t.end()
})
