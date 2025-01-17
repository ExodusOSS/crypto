'use strict'

const { sha256 } = require('@noble/hashes/sha256')
const { sha3_256, sha3_384, sha3_512 } = require('@noble/hashes/sha3') // eslint-disable-line camelcase
const { sha384, sha512, sha512_256 } = require('@noble/hashes/sha512') // eslint-disable-line camelcase
const { ripemd160 } = require('@noble/hashes/ripemd160')

function hash(type) {
  if (type === 'sha256') return sha256
  if (type === 'sha384') return sha384
  if (type === 'sha512') return sha512
  if (type === 'sha512-256') return sha512_256 // eslint-disable-line camelcase
  if (type === 'sha3-256') return sha3_256 // eslint-disable-line camelcase
  if (type === 'sha3-384') return sha3_384 // eslint-disable-line camelcase
  if (type === 'sha3-512') return sha3_512 // eslint-disable-line camelcase
  if (type === 'ripemd160') return ripemd160
  throw new Error('Unsupported hash type') // unreachable, guarded by input parameter checks
}

module.exports = { hash }
