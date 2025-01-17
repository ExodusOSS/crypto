// A version based on noble/curves, not included in release of exodus/crypto yet

import { sha512 } from '@noble/hashes/sha2'
import { blake2b } from '@noble/hashes/blake2b'
import * as curves from '@noble/curves/ed25519'
import { fromUint8Array } from '../../utils/output.js'
import { toUint8Array } from '../../utils/sodium.mjs'

export async function convertPublicKeyToX25519(publicKey) {
  return curves.edwardsToMontgomeryPub(toUint8Array(publicKey))
}

export async function convertPrivateKeyToX25519(privateKey) {
  return curves.edwardsToMontgomeryPriv(toUint8Array(privateKey).subarray(0, 32))
}

export async function genSignKeyPair(rawSeed) {
  const seed = toUint8Array(rawSeed)
  if (seed.length !== 32) throw new Error('expected 32 bytes of randomness as input')
  const keyType = 'ed25519'
  const publicKeyED = curves.ed25519.getPublicKey(seed)
  const privateKey = Buffer.concat([seed, publicKeyED])
  return { publicKey: fromUint8Array(publicKeyED), privateKey, keyType }
}

export async function genBoxKeyPair(rawSeed) {
  const seed = toUint8Array(rawSeed)
  if (seed.length !== 32) throw new Error('expected 32 bytes of randomness as input')
  const curve = 'x25519'
  const privateKeyX = sha512(seed).subarray(0, 32) // TODO: async
  const publicKeyX = curves.x25519.getPublicKey(privateKeyX)
  return { curve, privateKey: fromUint8Array(privateKeyX), publicKey: fromUint8Array(publicKeyX) }
}

export async function getSodiumKeysFromSeed(rawSeed) {
  const seed = toUint8Array(rawSeed)
  if (seed.length !== 32) throw new Error('expected 32 bytes of randomness as input')
  const publicKeyED = curves.ed25519.getPublicKey(seed)
  const privateKeyX = sha512(seed).subarray(0, 32) // TODO: async
  const publicKeyX = curves.x25519.getPublicKey(privateKeyX)
  return {
    box: {
      publicKey: fromUint8Array(publicKeyX),
      privateKey: fromUint8Array(privateKeyX),
      keyType: 'x25519',
    },
    sign: {
      publicKey: fromUint8Array(publicKeyED),
      privateKey: Buffer.concat([seed, publicKeyED]),
      keyType: 'ed25519',
    },
    secret: fromUint8Array(blake2b(seed, { dkLen: 32 })),
    derived: Buffer.from(seed), // copy
  }
}

const assert = (x, msg) => {
  if (!x) throw new Error(msg || 'Assertion failed')
}

export async function signDetached({ message, privateKey }) {
  assert(message instanceof Uint8Array, 'expected Buffer "message"')
  assert(privateKey instanceof Uint8Array, 'expected Buffer "privateKey"')
  return fromUint8Array(curves.ed25519.sign(message, privateKey.subarray(0, 32)))
}

export async function verifyDetached({ message, sig, publicKey }) {
  assert(message instanceof Uint8Array, 'expected Buffer "message"')
  assert(sig instanceof Uint8Array, 'expected Buffer "sig"')
  assert(publicKey instanceof Uint8Array, 'expected Buffer "publicKey"')
  return curves.ed25519.verify(sig, message, publicKey)
}

export async function sign({ message, privateKey }) {
  return Buffer.concat([await signDetached({ message, privateKey }), message])
}

export async function signOpen({ signed, publicKey }) {
  assert(signed instanceof Uint8Array, 'expected Buffer "signed"')
  const sig = signed.subarray(0, 64)
  const message = signed.subarray(64)
  if (!(await verifyDetached({ message, sig, publicKey }))) {
    throw new Error('incorrect signature for the given public key')
  }
  return Buffer.from(message) // copy
}
