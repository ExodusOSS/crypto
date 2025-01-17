'use strict'

const tape = require('@exodus/test/tape')

const { baseline, known, compare } = require('./util/hmac.js')

tape('hmac.native: hmac usage', async (t) => {
  const { hmac, hmacSync } = require('../hmac.native.js')
  await baseline(t, hmac)
  await baseline(t, async (...args) => hmacSync(...args))
})

tape('hmac.native: known pairs', async (t) => {
  const { hmac, hmacSync } = require('../hmac.native.js')
  await known(t, hmac)
  await known(t, hmacSync)
})

tape('hmac.native: random data hmac matches with hmac.node', async (t) => {
  const { hmac, hmacSync } = require('../hmac.native.js')
  const { hmacSync: node } = require('../hmac.node.js')
  await compare(t, node, hmac, hmacSync)
})
