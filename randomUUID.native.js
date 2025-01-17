'use strict'

// NOTE: not batched for code simplicity, if we need to optimize this, we can implement batching
// NOTE: not microoptimized, about 1.5x slower than crypto.randomUUID({ disableEntropyCache: true })
// This does get us about the same speed as uuid@3

// Expects globalThis.crypto.getRandomValues polyfill to work
// Can be polyfilled with react-native-get-random-values

let entropy

const hex = (start, end) => entropy.slice(start, end).toString('hex')

function randomUUID() {
  if (!entropy) entropy = Buffer.alloc(16)

  globalThis.crypto.getRandomValues(entropy)
  entropy[6] = (entropy[6] & 0x0f) | 0x40 // version 4: 0100xxxx
  entropy[8] = (entropy[8] & 0x3f) | 0x80 // variant 1: 10xxxxxx

  // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  return `${hex(0, 4)}-${hex(4, 6)}-${hex(6, 8)}-${hex(8, 10)}-${hex(10, 16)}`
}

module.exports = { randomUUID }
