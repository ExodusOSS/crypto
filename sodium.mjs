import { blake2b } from '@noble/hashes/blake2b'
import * as curve25519 from './curve25519.mjs'
import { fromUint8Array } from './utils/output.js'
import { toUint8Array } from './utils/sodium.mjs'
import { hash } from './hash.js'

function assertUint8(arr, size) {
  if (arr instanceof Uint8Array && arr.length === size) return
  throw new Error(`Expected an Uint8Array of size ${Number(size)}`)
}

// APIs compatible with https://npmjs.com/@exodus/sodium-crypto

export async function convertPublicKeyToX25519(publicKey) {
  return curve25519.edwardsToMontgomeryPublic({ publicKey: toUint8Array(publicKey) }) // uint8
}

export async function convertPrivateKeyToX25519(privateKey) {
  const privateKeyArr = toUint8Array(privateKey)
  assertUint8(privateKeyArr, 64)
  return curve25519.edwardsToMontgomeryPrivate({ privateKey: privateKeyArr.subarray(0, 32) }) // uint8
}

export async function genSignKeyPair(rawSeed) {
  const seed = toUint8Array(rawSeed)
  assertUint8(seed, 32)
  const publicKey = await curve25519.edwardsToPublic({ privateKey: seed, format: 'buffer' })
  const privateKey = Buffer.concat([seed, publicKey]) // sodium does that
  return { publicKey, privateKey, keyType: 'ed25519' }
}

export async function genBoxKeyPair(rawSeed) {
  const seed = toUint8Array(rawSeed)
  assertUint8(seed, 32)
  const privateKey = (await hash('sha512', seed, 'buffer')).subarray(0, 32)
  const publicKey = await curve25519.montgomeryToPublic({ privateKey, format: 'buffer' })
  return { publicKey, privateKey, curve: 'x25519' }
}

export async function getSodiumKeysFromSeed(rawSeed) {
  const seed = toUint8Array(rawSeed)
  assertUint8(seed, 32)
  const { curve: keyTypeBox, ...box } = await genBoxKeyPair(seed)
  return {
    box: { ...box, keyType: keyTypeBox },
    sign: await genSignKeyPair(seed),
    secret: fromUint8Array(blake2b(seed, { dkLen: 32 })),
    derived: Buffer.from(seed), // copy
  }
}

export async function signDetached({ message, privateKey }) {
  assertUint8(privateKey, 64)
  return curve25519.signDetached({
    message,
    privateKey: privateKey.subarray(0, 32),
    format: 'buffer',
  })
}

export async function verifyDetached({ message, sig, publicKey }) {
  return curve25519.verifyDetached({ message, signature: sig, publicKey })
}

export async function sign({ message, privateKey }) {
  assertUint8(privateKey, 64)
  return curve25519.signAttached({
    message,
    privateKey: privateKey.subarray(0, 32),
    format: 'buffer',
  })
}

export async function signOpen({ signed, publicKey }) {
  return curve25519.signOpen({ signed, publicKey, format: 'buffer' })
}
