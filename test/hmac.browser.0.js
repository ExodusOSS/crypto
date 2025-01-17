'use strict'

const tape = require('@exodus/test/tape')

delete globalThis.crypto

tape('hmac.browser: rejects without globalThis.crypto', async (t) => {
  const { hmac } = require('../hmac.browser.js')

  for (const type of ['sha256', 'sha384', 'sha512']) {
    await t.rejects(hmac(type, 'secret', ''))
    await t.rejects(hmac(type, 'secret', 'message'))
    await t.rejects(hmac(type, 'secret', 'message', 'hex'))
    await t.rejects(hmac(type, '', 'message'))
    await t.rejects(hmac(type, 'secret', 'message', 'base64'))
  }
  for (const type of ['sha1', 'md5', ['sha256']]) {
    await t.rejects(hmac(type, 'secret', 'message'))
    await t.rejects(hmac(type, 'secret', 'message', 'hex'))
  }
})

tape('hmacSync.browser: works without globalThis.crypto', (t) => {
  const { hmacSync } = require('../hmac.browser.js')

  for (const type of ['sha256', 'sha384', 'sha512']) {
    t.doesNotThrow(() => hmacSync(type, 'secret', '')) // invalid format
    t.doesNotThrow(() => hmacSync(type, 'secret', 'message'))
    t.doesNotThrow(() => hmacSync(type, 'secret', 'message', 'hex'))
    t.throws(() => hmacSync(type, '', 'message')) // invalid key
    t.throws(() => hmacSync(type, 'secret', 'message', 'base64')) // invalid format
  }
  for (const type of ['sha1', 'md5', ['sha256']]) {
    t.throws(() => hmacSync(type, 'secret', 'message')) // invalid type
    t.throws(() => hmacSync(type, 'secret', 'message', 'hex')) // invalid type
  }

  t.end()
})
