'use strict'

const tape = require('@exodus/test/tape')

const { baseline, known, compare } = require('./util/hmac.js')

tape('hmac.node: hmac usage', async (t) => {
  const { hmac, hmacSync } = require('../hmac.node.js')
  await baseline(t, hmac)
  await baseline(t, async (...args) => hmacSync(...args))
})

tape('hmac.node: known pairs', async (t) => {
  const { hmac, hmacSync } = require('../hmac.node.js')
  await known(t, hmac)
  await known(t, hmacSync)
})

tape('hmac.node: async matches sync', async (t) => {
  const { hmac, hmacSync } = require('../hmac.node.js')
  await compare(t, hmacSync, hmac)
})
