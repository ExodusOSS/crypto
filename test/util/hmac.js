'use strict'

const { randomBytes } = require('crypto')

const fixture = [
  ['sha256', 'secret', 'abc', '9946dad4e00e913fc8be8e5d3f7e110a4a9e832f83fb09c345285d78638d8a0e'],
  [
    'sha384',
    'some',
    'hello',
    '52cabf5e54f2df8e1345390bab95120cade51e953fa759ae62c291f5b73dc8c8fb2e3c628a37b862a9638abe92ce4f62',
  ],
  [
    'sha512',
    'what',
    'world',
    'e18f4c594e00791952af935f3d669b9c521d47092a4e8fa56cc9f1061a3f13a3ea84c94f75d96159da9ddd01cc3479e413c44c0b2a8ba86c6776e71344953a5a',
  ],
]

const baseline = async (t, hmac) => {
  for (const type of ['sha256', 'sha384', 'sha512']) {
    await t.doesNotReject(hmac(type, 'secret', ''))
    await t.doesNotReject(hmac(type, 'secret', 'message'))
    await t.doesNotReject(hmac(type, 'secret', 'message', 'hex'))
    await t.rejects(hmac(type, '', 'message'), /Zero-length key is not supported/)
    await t.rejects(hmac(type, 'secret', 'message', 'base64'), /Unsupported hash format/)
  }
  for (const type of ['sha1', 'md5', ['sha256']]) {
    await t.rejects(hmac(type, 'secret', 'message'), /Unsupported hash type/)
    await t.rejects(hmac(type, 'secret', 'message', 'hex'), /Unsupported hash type/)
  }
}

const known = async (t, hmac) => {
  for (const [type, secret, input, result] of fixture) {
    t.strictEqual(await hmac(type, secret, input, 'hex'), result)
    t.deepEqual(await hmac(type, secret, input), Buffer.from(result, 'hex'))
    t.strictEqual(await hmac(type, Buffer.from(secret), input, 'hex'), result)
    t.deepEqual(await hmac(type, Buffer.from(secret), input), Buffer.from(result, 'hex'))
    t.strictEqual(await hmac(type, secret, Buffer.from(input), 'hex'), result)
    t.deepEqual(await hmac(type, secret, Buffer.from(input)), Buffer.from(result, 'hex'))
    t.strictEqual(await hmac(type, Buffer.from(secret), Buffer.from(input), 'hex'), result)
    t.deepEqual(
      await hmac(type, Buffer.from(secret), Buffer.from(input)),
      Buffer.from(result, 'hex')
    )
    t.deepEqual(
      await hmac(type, Buffer.from(secret), Buffer.from(input), 'buffer'),
      Buffer.from(result, 'hex')
    )
    t.deepEqual(
      await hmac(type, Buffer.from(secret), Buffer.from(input), 'uint8'),
      new Uint8Array(Buffer.from(result, 'hex'))
    )
    t.strictEqual(await hmac(type, secret, [Buffer.from(input)], 'hex'), result)
    t.strictEqual(await hmac(type, secret, [Buffer.alloc(0), Buffer.from(input)], 'hex'), result)
    t.deepEqual(
      await hmac(type, secret, [
        Buffer.alloc(0),
        Buffer.from(input.slice(0, 2)),
        Buffer.alloc(0),
        Buffer.from(input.slice(2)),
        Buffer.alloc(0),
      ]),
      Buffer.from(result, 'hex')
    )
    t.strictEqual(
      await hmac(type, secret, [...Buffer.from(input)].map((c) => new Uint8Array([c])), 'hex'),
      result
    )
  }
}

const compare = async (t, first, ...rest) => {
  t.ok(rest.length > 0)
  for (let i = 0; i < 300; i++) {
    for (const type of ['sha256', 'sha384', 'sha512']) {
      const lengthSecret = 1 + (i % 3 === 0 ? i : Math.floor(Math.random() * 10000))
      const secret = randomBytes(lengthSecret)
      const length = i < 100 ? i * 10 : Math.floor(Math.random() * 10000)
      const data = randomBytes(length)
      const expected = first(type, secret, data, 'hex') // first is either the sync one or node sync
      for (const hmac of rest) {
        t.strictEqual(await hmac(type, secret, data, 'hex'), expected)
      }
    }
  }
}

module.exports = { baseline, known, compare }
