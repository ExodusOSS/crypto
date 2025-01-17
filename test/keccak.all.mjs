import test from '@exodus/test/tape'
import createKeccakHash from 'keccak'
import { randomBytes } from 'crypto'

import { keccak224, keccak256, keccak384, keccak512 } from '../keccak.mjs'

// https://www.npmjs.com/package/keccak256
// https://github.com/miguelmota/keccak256/blob/master/test/keccak256.js#L1C1-L9C3
test('keccak256', (t) => {
  t.plan(2)
  t.equal(
    keccak256('hello').toString('hex'),
    '1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
  )
  t.equal(
    keccak256(Buffer.from('hello')).toString('hex'),
    '1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
  )
})

test('array input', (t) => {
  for (const keccak of [keccak224, keccak256, keccak384, keccak512]) {
    for (const input of [Buffer.from('hello'), randomBytes(20)]) {
      const expected = keccak(input, 'hex')
      t.strictEqual(keccak([input], 'hex'), expected)
      t.strictEqual(keccak([Buffer.alloc(0), input], 'hex'), expected)
      t.deepEqual(
        keccak([
          Buffer.alloc(0),
          input.subarray(0, 2),
          new Uint8Array(0),
          input.subarray(2),
          Buffer.alloc(0),
        ]),
        Buffer.from(expected, 'hex')
      )
      t.strictEqual(keccak([...input].map((c) => new Uint8Array([c])), 'hex'), expected)
    }
  }
  t.end()
})

// https://www.npmjs.com/package/keccak
// https://github.com/cryptocoinjs/keccak/blob/master/test/vectors-keccak.js
test('keccak', (t) => {
  const vectors = [
    [keccak224, '', 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd'],
    [keccak256, '', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
    [
      keccak384,
      '',
      '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff',
    ],
    [
      keccak512,
      '',
      '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e',
    ],
  ]
  for (const [keccak, input, expected] of vectors) {
    t.equal(keccak(input).toString('hex'), expected)
    t.equal(keccak(input, 'hex'), expected)
    t.equal(keccak(Buffer.from(input), 'hex'), expected)
    t.deepEqual(keccak(input), Buffer.from(expected, 'hex'))
  }
  t.end()
})

test('random data hash matches with keccak', (t) => {
  const keccak = (type, data, format) =>
    createKeccakHash(type)
      .update(data)
      .digest(format)
  for (let i = 0; i < 300; i++) {
    const length = i < 100 ? i * 10 : Math.floor(Math.random() * 10000)
    const data = randomBytes(length)
    t.equal(keccak224(data, 'hex'), keccak('keccak224', data, 'hex'))
    t.deepEqual(keccak224(data), keccak('keccak224', data))
    t.equal(keccak256(data, 'hex'), keccak('keccak256', data, 'hex'))
    t.deepEqual(keccak256(data), keccak('keccak256', data))
    t.equal(keccak384(data, 'hex'), keccak('keccak384', data, 'hex'))
    t.deepEqual(keccak384(data), keccak('keccak384', data))
    t.equal(keccak512(data, 'hex'), keccak('keccak512', data, 'hex'))
    t.deepEqual(keccak512(data), keccak('keccak512', data))
  }
  t.end()
})

test('formats', (t) => {
  const data = randomBytes(100)
  t.ok(Buffer.isBuffer(data))

  const res = {
    default: keccak256(data),
    hex: keccak256(data, 'hex'),
    buffer: keccak256(data, 'buffer'),
    uint8: keccak256(data, 'uint8'),
  }

  t.ok(typeof res.hex === 'string')
  t.ok(Buffer.isBuffer(res.default))
  t.ok(Buffer.isBuffer(res.buffer))
  t.ok(!Buffer.isBuffer(res.uint8))
  t.ok(Object.getPrototypeOf(res.uint8) === Uint8Array.prototype)

  t.equal(res.buffer.length, res.uint8.length)
  t.equal(res.buffer.length * 2, res.hex.length)

  for (const type of ['', 'unknown', 'utf-8', 'utf8']) {
    t.throws(() => keccak256(data, type))
  }

  t.deepEqual(res.default, res.buffer)
  t.deepEqual(
    res.default,
    createKeccakHash('keccak256')
      .update(data)
      .digest()
  )
  t.deepEqual(
    res.hex,
    createKeccakHash('keccak256')
      .update(data)
      .digest('hex')
  )
  t.deepEqual(res.buffer.toString('hex'), res.hex)
  t.deepEqual(Buffer.from(res.uint8), res.buffer)

  t.end()
})
