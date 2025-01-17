'use strict'

const tape = require('@exodus/test/tape')

delete globalThis.crypto

tape('hash.browser: rejects without globalThis.crypto', async (t) => {
  const { hash } = require('../hash.browser.js')

  for (const type of ['sha256', 'sha384', 'sha512']) {
    await t.rejects(hash(type, ''))
    await t.rejects(hash(type, '', 'hex'))
    await t.rejects(hash(type, '', 'base64'))
  }
  for (const type of ['sha1', 'md5', ['sha256']]) {
    await t.rejects(hash(type, ''))
    await t.rejects(hash(type, '', 'hex'))
  }
})

tape('hashSync.browser: works without globalThis.crypto', (t) => {
  t.doesNotThrow(() => {
    const { hashSync } = require('../hash.browser.js')

    for (const type of ['sha256', 'sha384', 'sha512', 'ripemd160']) {
      t.doesNotThrow(() => hashSync(type, ''))
      t.doesNotThrow(() => hashSync(type, '', 'hex'))
      t.throws(() => hashSync(type, '', 'base64')) // invalid format
    }
    for (const type of ['sha1', 'md5', ['sha256']]) {
      t.throws(() => hashSync(type, '')) // invalid type
      t.throws(() => hashSync(type, '', 'hex')) // invalid type
    }
  })

  t.end()
})
