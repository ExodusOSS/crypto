import test from '@exodus/test/tape'
import { randomBytes } from 'crypto'
import { blake2b as blake2bBlakeJS } from '@exodus/blakejs'

import { blake2b, blake2bWithOptions } from '../blake2b.mjs'
import { compareRaw } from './util/hash.js'

// A small part of https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json
test('blake', (t) => {
  const vectors = [
    [
      blake2b,
      '',
      '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
    ],
    [
      blake2b,
      '00',
      '2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b',
    ],
    [
      blake2b,
      '0001',
      '1c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5',
    ],
    [
      blake2b,
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe',
      '5b21c5fd8868367612474fa2e70e9cfa2201ffeee8fafab5797ad58fefa17c9b5b107da4a3db6320baaf2c8617d5a51df914ae88da3867c2d41f0cc14fa67928',
    ],
  ]
  for (const [blake, hex, expected] of vectors) {
    const input = Buffer.from(hex, 'hex')
    t.equal(blake(input).toString('hex'), expected)
    t.equal(blake(input, 'hex'), expected)
    t.deepEqual(blake(input), Buffer.from(expected, 'hex'))
  }
  t.end()
})

test('array input', (t) => {
  for (const blake of [blake2b, blake2bWithOptions({ size: 20 })]) {
    for (const input of [Buffer.from('hello'), randomBytes(20)]) {
      const expected = blake(input, 'hex')
      t.strictEqual(blake([input], 'hex'), expected)
      t.strictEqual(blake([Buffer.alloc(0), input], 'hex'), expected)
      t.deepEqual(
        blake([
          Buffer.alloc(0),
          input.subarray(0, 2),
          new Uint8Array(0),
          input.subarray(2),
          Buffer.alloc(0),
        ]),
        Buffer.from(expected, 'hex')
      )
      t.strictEqual(blake([...input].map((c) => new Uint8Array([c])), 'hex'), expected)
    }
  }
  t.end()
})

test('random data hash matches with blakejs', async (t) => {
  await compareRaw(t, (data, format) => Buffer.from(blake2bBlakeJS(data)).toString(format), blake2b)
  await compareRaw(
    t,
    (data, format) => Buffer.from(blake2bBlakeJS(data, null, 20)).toString(format),
    blake2bWithOptions({ size: 20 })
  )
  t.end()
})

test('formats', (t) => {
  const data = randomBytes(100)
  t.ok(Buffer.isBuffer(data))

  const res = {
    default: blake2b(data),
    hex: blake2b(data, 'hex'),
    buffer: blake2b(data, 'buffer'),
    uint8: blake2b(data, 'uint8'),
  }

  t.ok(typeof res.hex === 'string')
  t.ok(Buffer.isBuffer(res.default))
  t.ok(Buffer.isBuffer(res.buffer))
  t.ok(!Buffer.isBuffer(res.uint8))
  t.ok(Object.getPrototypeOf(res.uint8) === Uint8Array.prototype)

  t.equal(res.buffer.length, res.uint8.length)
  t.equal(res.buffer.length * 2, res.hex.length)

  for (const type of ['', 'unknown', 'utf-8', 'utf8']) {
    t.throws(() => blake2b(data, type))
  }

  t.deepEqual(res.default, res.buffer)
  t.deepEqual(res.buffer.toString('hex'), res.hex)
  t.deepEqual(Buffer.from(res.uint8), res.buffer)

  t.end()
})
