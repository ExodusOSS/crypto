import * as ed25519 from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'

// From doc, we need this for sync methods to work, @noble/ed25519 does not ship sha512
if (!ed25519.utils.sha512Sync) {
  ed25519.utils.sha512Sync = (...m) => sha512(ed25519.utils.concatBytes(...m))
}

// @noble/ed25519 might falsely auto-detect that we are inside node, trusting bundlers to resolve 'crypto' to undefined in browsers
// The only things that affects are randomness source (which we recheck) and sha512 implementation
// We want to be sure to not use the sha512 one from crypto-browserify
// When web crypto is available, it defaults to that, otherwise it defaults to attempting to use node crypto (which might be fake)
// Also when web crypto is just a RN randomBytes polyfill it might also fail in sha512
const hasNode = typeof process === 'object' && !process.browser // likely has native 'crypto' module, we don't want to override that
if (!hasNode && !globalThis.crypto?.subtle?.digest) {
  if (!globalThis.crypto?.getRandomValues) throw new Error('global crypto.getRandomValues required')
  ed25519.utils.sha512 = ed25519.utils.sha512Sync
}

// All methods here accept and return Uint8Array instances of fixed size
const assertUint8AnySize = (arr) => assertUint8(arr, arr.byteLength)
function assertUint8(arr, size) {
  if (arr instanceof Uint8Array && arr.length === size) return
  throw new Error(`Expected an Uint8Array of size ${Number(size)}`)
}

// Exports

export const edwardsToMontgomeryPublic = async (publicKeyED) =>
  edwardsToMontgomeryPublicSync(publicKeyED)
export function edwardsToMontgomeryPublicSync(publicKeyED) {
  assertUint8(publicKeyED, 32)
  return ed25519.Point.fromHex(publicKeyED).toX25519()
}

export async function edwardsToMontgomeryPrivate(privateKeyED) {
  assertUint8(privateKeyED, 32)
  return (await ed25519.utils.getExtendedPublicKey(privateKeyED)).head
}

export function edwardsToMontgomeryPrivateSync(privateKeyED) {
  assertUint8(privateKeyED, 32)
  return ed25519.sync.getExtendedPublicKey(privateKeyED).head
}

export async function edwardsToPublic(privateKey) {
  assertUint8(privateKey, 32)
  return ed25519.getPublicKey(privateKey)
}

export function edwardsToPublicSync(privateKey) {
  assertUint8(privateKey, 32)
  return ed25519.sync.getPublicKey(privateKey)
}

export const montgomeryToPublic = async (privateKey) => montgomeryToPublicSync(privateKey)
export function montgomeryToPublicSync(privateKey) {
  assertUint8(privateKey, 32)
  // aka @noble/ed25519.curve25519.scalarMultBase(
  // aka @noble/curves/ed25519.x25519.getPublicKey(
  // aka @noble/curves/ed25519.x25519.scalarMultBase(
  return ed25519.curve25519.scalarMultBase(privateKey)
}

export async function sign(message, privateKey) {
  assertUint8(privateKey, 32)
  assertUint8AnySize(message)
  return ed25519.sign(message, privateKey)
}

export function signSync(message, privateKey) {
  assertUint8(privateKey, 32)
  assertUint8AnySize(message)
  return ed25519.sync.sign(message, privateKey)
}

export async function verify(signature, message, publicKey) {
  assertUint8(publicKey, 32)
  assertUint8(signature, 64)
  assertUint8AnySize(message)
  try {
    // @noble/ed25519 might throw on invalid/corrupted signatures in .verify, catch that and return as false
    const valid = await ed25519.verify(signature, message, publicKey)
    // Need to await above for try-catch
    return valid
  } catch {
    return false
  }
}

export function verifySync(signature, message, publicKey) {
  assertUint8(publicKey, 32)
  assertUint8(signature, 64)
  assertUint8AnySize(message)
  try {
    // @noble/ed25519 might throw on invalid/corrupted signatures in .verify, catch that and return as false
    return ed25519.sync.verify(signature, message, publicKey)
  } catch {
    return false
  }
}

export const getSharedSecretMontgomery = async (privateKey, publicKey) =>
  getSharedSecretMontgomerySync(privateKey, publicKey)
export function getSharedSecretMontgomerySync(privateKey, publicKey) {
  assertUint8(privateKey, 32)
  assertUint8(publicKey, 32)
  // aka @noble/ed25519/curve25519.scalarMult(
  // aka @noble/curves/ed25519.x25519.getSharedSecret(
  // aka @noble/curves/ed25519.x25519.scalarMult(
  return ed25519.curve25519.scalarMult(privateKey, publicKey)
}

export async function getSharedSecretEdwards(privateKey, publicKey) {
  assertUint8(privateKey, 32)
  assertUint8(publicKey, 32)
  return ed25519.getSharedSecret(privateKey, publicKey)
}

export function getSharedSecretEdwardsSync(privateKey, publicKey) {
  // Same as @noble/ed25519.getSharedSecret( does, but sync
  return getSharedSecretMontgomerySync(
    edwardsToMontgomeryPrivateSync(privateKey),
    edwardsToMontgomeryPublicSync(publicKey)
  )
}
