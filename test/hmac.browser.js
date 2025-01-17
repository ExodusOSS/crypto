'use strict'

const tape = require('@exodus/test/tape')

const { baseline, known, compare } = require('./util/hmac.js')

if (!globalThis.crypto) globalThis.crypto = require('crypto').webcrypto

tape('hmac.browser: hmac usage', async (t) => {
  const { hmac, hmacSync } = require('../hmac.browser.js')
  await baseline(t, hmac)
  await baseline(t, async (...args) => hmacSync(...args))
})

tape('hmac.browser: known pairs', async (t) => {
  const { hmac, hmacSync } = require('../hmac.browser.js')
  await known(t, hmac)
  await known(t, hmacSync)
})

tape('hmac.browser: random data hmac matches with hmac.node', async (t) => {
  const { hmac, hmacSync } = require('../hmac.browser.js')
  const { hmacSync: node } = require('../hmac.node.js')
  await compare(t, node, hmac, hmacSync)
})
