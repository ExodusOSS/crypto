import * as curve25519 from './utils/curve25519.mjs'
import { fromUint8Super } from './utils/output.js'

// This API operates on any Uint8Array instances and returns Uint8Array instances by default
// It accepts additional `format` parameter to override, e.g. to return Buffer instances or hex

// As a design decision, this library currently accepts 32-byte ED private keys, not 64-byte private:public combinations
// This removes the need to validate them and follows what noble implemented
// Wrappers can manage key storage/processing themselves
// See e.g. https://github.com/dchest/tweetnacl-js/issues/247 for context

const assert = (x, msg) => {
  if (!x) throw new Error(msg || 'Assertion failed')
}

/* Key conversion */

export async function edwardsToMontgomeryPublic({ publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.edwardsToMontgomeryPublic(publicKey), format)
}

export function edwardsToMontgomeryPublicSync({ publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.edwardsToMontgomeryPublicSync(publicKey), format)
}

// Note: 64-byte private:public keys are not accepted
export async function edwardsToMontgomeryPrivate({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.edwardsToMontgomeryPrivate(privateKey), format)
}

export function edwardsToMontgomeryPrivateSync({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.edwardsToMontgomeryPrivateSync(privateKey), format)
}

export async function edwardsToPublic({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.edwardsToPublic(privateKey), format)
}

export function edwardsToPublicSync({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.edwardsToPublicSync(privateKey), format)
}

export async function montgomeryToPublic({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.montgomeryToPublic(privateKey), format)
}

export function montgomeryToPublicSync({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.montgomeryToPublicSync(privateKey), format)
}

/* Shared secrets */

export async function getSharedSecretMontgomery({ privateKey, publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.getSharedSecretMontgomery(privateKey, publicKey), format)
}

export function getSharedSecretMontgomerySync({ privateKey, publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.getSharedSecretMontgomerySync(privateKey, publicKey), format)
}

export async function getSharedSecretEdwards({ privateKey, publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.getSharedSecretEdwards(privateKey, publicKey), format)
}

export function getSharedSecretEdwardsSync({ privateKey, publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.getSharedSecretEdwardsSync(privateKey, publicKey), format)
}

/* Detached signatures */

// Note: 64-byte private:public keys are not accepted
export async function signDetached({ message, privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(await curve25519.sign(message, privateKey), format)
}
export function signDetachedSync({ message, privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return fromUint8Super(curve25519.signSync(message, privateKey), format)
}

export async function verifyDetached({ message, signature, publicKey, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return curve25519.verify(signature, message, publicKey)
}
export function verifyDetachedSync({ message, signature, publicKey, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return curve25519.verifySync(signature, message, publicKey)
}

/* Attached signatures */
// These do not accept format option and always return Buffers

const signatureErrorMessage = 'incorrect signature for the given public key'
function splitSignedAttached(signed) {
  assert(signed instanceof Uint8Array, 'expected "signed" to be an Uint8Array intance')
  const signature = signed.subarray(0, 64)
  const message = signed.subarray(64)
  return { signature, message }
}

// Note: 64-byte private:public keys are not accepted
export async function signAttached({ message, privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  const signed = Buffer.concat([await signDetached({ message, privateKey }), message])
  return fromUint8Super(signed, format)
}

export function signAttachedSync({ message, privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  const signed = Buffer.concat([signDetachedSync({ message, privateKey }), message])
  return fromUint8Super(signed, format)
}

export async function signOpen({ signed, publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  const { message, signature } = splitSignedAttached(signed)
  assert(await verifyDetached({ message, signature, publicKey }), signatureErrorMessage)
  const opened = Buffer.from(message) // create a copy on a purpose, we don't want 'signed' corruption to leak into output
  return fromUint8Super(opened, format)
}

export function signOpenSync({ signed, publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  const { message, signature } = splitSignedAttached(signed)
  assert(verifyDetachedSync({ message, signature, publicKey }), signatureErrorMessage)
  const opened = Buffer.from(message) // create a copy on a purpose, we don't want 'signed' corruption to leak into output
  return fromUint8Super(opened, format)
}
