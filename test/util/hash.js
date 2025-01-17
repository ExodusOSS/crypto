'use strict'

const { randomBytes, createHash: createHashNode } = require('crypto')
const createHashJS = require('create-hash/browser.js')
const shajs = require('sha.js')
const keccak = require('keccak')

// Patch sha.js to support sha512-256 for comparison with it
// Refs: https://github.com/browserify/sha.js/pull/67
if (!shajs.sha512) throw new Error('unexpected')
if (!shajs['sha512-256']) {
  // eslint-disable-next-line camelcase
  shajs['sha512-256'] = class Sha512_256 extends shajs.sha512 {
    init() {
      this._ah = 0x22312194
      this._bh = 0x9f555fa3
      this._ch = 0x2393b86b
      this._dh = 0x96387719
      this._eh = 0x96283ee2
      this._fh = 0xbe5e1e25
      this._gh = 0x2b0199fc
      this._hh = 0x0eb72ddc

      this._al = 0xfc2bf72c
      this._bl = 0xc84c64c2
      this._cl = 0x6f53b151
      this._dl = 0x5940eabd
      this._el = 0xa88effe3
      this._fl = 0x53863992
      this._gl = 0x2c85b8aa
      this._hl = 0x81c52ca2

      return this
    }

    _hash() {
      return super._hash().slice(0, 256 / 8)
    }
  }
}
shajs['sha3-256'] = function() {
  return keccak('sha3-256')
}
shajs['sha3-384'] = function() {
  return keccak('sha3-384')
}
shajs['sha3-512'] = function() {
  return keccak('sha3-512')
}

const fixture = [
  ['sha256', 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  [
    'sha384',
    'hello',
    '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f',
  ],
  [
    'sha512',
    'world',
    '11853df40f4b2b919d3815f64792e58d08663767a494bcbb38c0b2389d9140bbb170281b4a847be7757bde12c9cd0054ce3652d0ad3a1a0c92babb69798246ee',
  ],
  ['sha512-256', 'world', 'b8007fc640bef3e2f10ea7ad9681f6fdbd132887406960f365452ba0a15e65e2'],
  ['sha3-256', 'world', '420baf620e3fcd9b3715b42b92506e9304d56e02d3a103499a3a292560cb66b2'],
  [
    'sha3-384',
    'world',
    '693ff8ff69391116b2763613c60b560fbba523ecbad06e2e93a0511239cea39a272614535f6a4c7dc6d1ea6f477563a4',
  ],
  [
    'sha3-512',
    'world',
    '6ec5025ab9e3f5c74d15fb95404746c24ff11d3a4b597e2eab26f938d42aa2fd2a47e2e48e314372d129a5b6db88e63e315bb99273612641da44630d842fb6d9',
  ],
  ['ripemd160', 'world', 'dbd32a04286f48676f2308fbcf30cc3202286de7'],
  ['hash160', 'world', '5fc3735525b88f0989429ea73a5bbf6cd61f0805'],
  ['p2sh-hash160', 'world', '9439ba1820dc596e74a72fa107f3246fccb8a337'],
]

const TYPES = [
  ...['sha256', 'sha384', 'sha512', 'sha512-256'], // SHA-2
  ...['sha3-256', 'sha3-384', 'sha3-512'], // SHA-3
  'ripemd160',
]

const baseline = async (t, hash) => {
  for (const type of TYPES) {
    await t.doesNotReject(hash(type, ''))
    await t.doesNotReject(hash(type, '', 'hex'))
    await t.rejects(hash(type, '', 'base64'), /Unsupported hash format/)
    await t.rejects(hash(type, {}), /Unsupported hash argument/)
    await t.rejects(hash(type, []), /An array in hash argument must not be empty/)
    await t.rejects(hash(type, ['']), / Unsupported entry in hash argument/)
    await t.doesNotReject(hash(type, [Buffer.alloc(0)]), /Unsupported hash format/)
  }
  for (const type of ['sha1', 'md5', ['sha256']]) {
    await t.rejects(hash(type, ''), /Unsupported hash type/)
    await t.rejects(hash(type, '', 'hex'), /Unsupported hash type/)
  }
}

const known = async (t, hash) => {
  for (const [type, input, result] of fixture) {
    t.strictEqual(await hash(type, input, 'hex'), result)
    t.deepEqual(await hash(type, input), Buffer.from(result, 'hex'))
    t.strictEqual(await hash(type, Buffer.from(input), 'hex'), result)
    t.deepEqual(await hash(type, Buffer.from(input)), Buffer.from(result, 'hex'))
    t.deepEqual(await hash(type, Buffer.from(input), 'buffer'), Buffer.from(result, 'hex'))
    t.deepEqual(
      await hash(type, Buffer.from(input), 'uint8'),
      new Uint8Array(Buffer.from(result, 'hex'))
    )
    t.strictEqual(await hash(type, [Buffer.from(input)], 'hex'), result)
    t.strictEqual(await hash(type, [Buffer.alloc(0), Buffer.from(input)], 'hex'), result)
    t.deepEqual(
      await hash(type, [
        Buffer.alloc(0),
        Buffer.from(input.slice(0, 2)),
        Buffer.alloc(0),
        Buffer.from(input.slice(2)),
        Buffer.alloc(0),
      ]),
      Buffer.from(result, 'hex')
    )
    t.strictEqual(
      await hash(type, [...Buffer.from(input)].map((c) => new Uint8Array([c])), 'hex'),
      result
    )
  }
}

const compare = async (t, ...hashes) => {
  t.ok(hashes.length > 0)
  const wrap = (createHash) => (type, data, format) =>
    createHash(type)
      .update(Array.isArray(data) ? Buffer.concat(data) : data)
      .digest(format)
  const [first, ...rest] = [wrap(createHashNode), wrap(createHashJS), ...hashes]
  for (let i = 0; i < 300; i++) {
    for (const type of TYPES) {
      const length = i < 100 ? i * 10 : Math.floor(Math.random() * 10000)
      const data = randomBytes(length)
      const expected = first(type, data, 'hex') // first is either the sync one or node sync
      for (const hash of rest) {
        t.strictEqual(await hash(type, data, 'hex'), expected)
      }
    }
  }
}

const compareRaw = async (t, first, ...rest) => {
  t.ok(rest.length > 0)
  for (let i = 0; i < 300; i++) {
    const length = i < 100 ? i * 10 : Math.floor(Math.random() * 10000)
    const data = randomBytes(length)
    const expected = first(data, 'hex') // first is either the sync one or node sync
    for (const hash of rest) {
      t.strictEqual(await hash(data, 'hex'), expected)
    }
  }
}

module.exports = { baseline, known, compare, compareRaw }
