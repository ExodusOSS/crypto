import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import * as secp256k1 from '@noble/secp256k1'
import { fromUint8Super } from './utils/output.js'

// This API operates on any Uint8Array instances and returns Uint8Array instances by default
// It accepts additional `format` parameter to override, e.g. to return Buffer instances or hex

const { utils } = secp256k1
const _1n = BigInt(1)

// From doc, we need this for sync methods to work, @noble/secp256k1 does not ship sha256
if (!utils.sha256Sync) utils.sha256Sync = (...msgs) => sha256(utils.concatBytes(...msgs))
if (!utils.hmacSha256Sync) {
  utils.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, utils.concatBytes(...msgs))
}

// @noble/secp256k1 might falsely auto-detect that we are inside node, trusting bundlers to resolve 'crypto' to undefined in browsers
// The only things that affects are randomness source (which we recheck) and sha256/hmac implementation
// We want to be sure to not use sha256/hmac from crypto-browserify
// When web crypto is available, it defaults to that, otherwise it defaults to attempting to use node crypto (which might be fake)
// Also when web crypto is just a RN randomBytes polyfill it might also fail in sha256/hmac
const hasNode = typeof process === 'object' && !process.browser // likely has native 'crypto' module, we don't want to override that
if (!hasNode && !globalThis.crypto?.subtle?.digest) {
  if (!globalThis.crypto?.getRandomValues) throw new Error('global crypto.getRandomValues required')
  utils.sha256 = utils.sha256Sync
  utils.hmacSha256 = utils.hmacSha256Sync
}

const assert = (x, msg) => {
  if (!x) throw new Error(msg || 'Assertion failed')
}

const isUint8 = (arr, size) => arr instanceof Uint8Array && arr.length === size
const assertUint8AnySize = (arr) => assert(arr instanceof Uint8Array, 'Expected an Uint8Array')

function assertUint8(arr, size) {
  if (!isUint8(arr, size)) throw new Error(`Expected an Uint8Array of size ${Number(size)}`) // don't concat in advance
}

function assertUint8PublicKeyLength(publicKey) {
  assertUint8AnySize(publicKey)
  assert(publicKey.length === 33 || publicKey.length === 65, 'Invalid public key length')
}

const INVALID_TWEAK_MESSAGE = 'Invalid tweak result'

// Key types:
// 32-byte private key
// 32-byte point aka public key, X coordinate only
// 33 = 1 + 32 "compressed" DER-encoded point / public key, X only, prefix is 02 or 03 (even or odd Y)
// 65 = 1 + 32 + 32 "uncompressed" DER-encoded point / public key, X and Y, prefix is 04

/* Keys */

export function privateKeyIsValid({ privateKey, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  return isUint8(privateKey, 32) && utils.isValidPrivateKey(privateKey)
}

export function privateKeyToPublicKey({ privateKey, compressed = true, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  assert(typeof compressed === 'boolean', '"compressed" should be boolean or undefined')
  const publicKey = secp256k1.getPublicKey(privateKey, compressed) // this performs validation and throws on invalid private keys
  return fromUint8Super(publicKey, format)
}

function publicKeyLengthIsValid(length, compressed) {
  if (compressed === undefined) return length === 33 || length === 65
  assert(typeof compressed === 'boolean', '"compressed" should be boolean or undefined')
  return length === (compressed ? 33 : 65)
}

export function publicKeyIsValid({ publicKey, compressed, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  if (!(publicKey instanceof Uint8Array)) return false
  if (!publicKeyLengthIsValid(publicKey.length, compressed)) return false
  try {
    return Boolean(secp256k1.Point.fromHex(publicKey))
  } catch {
    return false
  }
}

export function publicKeyConvert({ publicKey, compressed, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8PublicKeyLength(publicKey)
  assert(typeof compressed === 'boolean', '"compressed" should be boolean') // no default to not cause confusion with noop tiny-secp256k1
  const converted = secp256k1.Point.fromHex(publicKey).toRawBytes(compressed) // Always create a copy. This also verifies the public key
  return fromUint8Super(converted, format)
}

export function publicKeyToX({ publicKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8PublicKeyLength(publicKey)
  const xOnly = Uint8Array.prototype.slice.call(publicKey, 1, 33) // copy, could be Uint8Array or a superclass e.g. Buffer
  return fromUint8Super(xOnly, format)
}

export function xOnlyIsValid({ xOnly, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(xOnly, 32)
  try {
    return Boolean(secp256k1.Point.fromHex(xOnly))
  } catch {
    return false
  }
}

/* Tweaks */

function parseTweak(tweak) {
  assertUint8(tweak, 32)
  const t = BigInt(`0x${secp256k1.utils.bytesToHex(tweak)}`) // bytesToHex checks for Uint8Array and always returns a string
  assert(t < secp256k1.CURVE.n, 'Tweak is malformed')
  return t
}

export function privateKeyTweakAdd({ privateKey, tweak, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  const t = parseTweak(tweak) // asserts
  const p = utils._normalizePrivateKey(privateKey) // asserts as checking private key validity
  const res = utils._bigintTo32Bytes(utils.mod(p + t, secp256k1.CURVE.n))
  assert(utils.isValidPrivateKey(res), INVALID_TWEAK_MESSAGE)
  return fromUint8Super(res, format)
}

export function privateKeyTweakSubtract({ privateKey, tweak, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  const t = parseTweak(tweak) // asserts
  const p = utils._normalizePrivateKey(privateKey) // asserts as checking private key validity
  const res = utils._bigintTo32Bytes(utils.mod(p - t, secp256k1.CURVE.n))
  assert(utils.isValidPrivateKey(res), INVALID_TWEAK_MESSAGE)
  return fromUint8Super(res, format)
}

export function privateKeyTweakNegate({ privateKey, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  const p = utils._normalizePrivateKey(privateKey) // asserts as checking private key validity
  const res = utils._bigintTo32Bytes(secp256k1.CURVE.n - p)
  assert(utils.isValidPrivateKey(res), INVALID_TWEAK_MESSAGE)
  return fromUint8Super(res, format)
}

// For public keys, the result of the tweak defaults to the same compression as the original
const defaultCompressedValue = (publicKey) => publicKey?.length === 33 // value only needed when publicKey is valid

export function publicKeyTweakAddPoint({
  publicKey,
  tweakPoint,
  compressed = defaultCompressedValue(publicKey),
  format,
  ...rest
}) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8PublicKeyLength(publicKey)
  assertUint8PublicKeyLength(tweakPoint)
  assert(typeof compressed === 'boolean', '"compressed" should be boolean')
  const P = secp256k1.Point.fromHex(publicKey) // asserts
  const T = secp256k1.Point.fromHex(tweakPoint) // asserts
  if (P.equals(T.negate())) throw new Error(INVALID_TWEAK_MESSAGE) // 0
  const Q = P.add(T)
  if (!Q) throw new Error(INVALID_TWEAK_MESSAGE)
  return fromUint8Super(Q.toRawBytes(compressed), format)
}

export function publicKeyTweakAddScalar({
  publicKey,
  tweak,
  compressed = defaultCompressedValue(publicKey),
  format,
  ...rest
}) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8PublicKeyLength(publicKey)
  assert(typeof compressed === 'boolean', '"compressed" should be boolean')
  const P = secp256k1.Point.fromHex(publicKey) // asserts
  const t = parseTweak(tweak) // asserts
  const Q = secp256k1.Point.BASE.multiplyAndAddUnsafe(P, t, _1n)
  if (!Q) throw new Error(INVALID_TWEAK_MESSAGE)
  return fromUint8Super(Q.toRawBytes(compressed), format)
}

export function publicKeyTweakMultiply({
  publicKey,
  tweak,
  compressed = defaultCompressedValue(publicKey),
  format,
  ...rest
}) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8PublicKeyLength(publicKey)
  assert(typeof compressed === 'boolean', '"compressed" should be boolean')
  const P = secp256k1.Point.fromHex(publicKey) // asserts
  const t = parseTweak(tweak) // asserts
  const Q = P.multiply(t)
  if (!Q) throw new Error(INVALID_TWEAK_MESSAGE)
  return fromUint8Super(Q.toRawBytes(compressed), format)
}

// returns a public key, not just x
export function xOnlyTweakAdd({ xOnly, tweak, format, compressed = true, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(xOnly, 32)
  assert(typeof compressed === 'boolean', '"compressed" should be boolean')
  const P = secp256k1.Point.fromHex(xOnly) // asserts
  const t = parseTweak(tweak) // asserts
  const Q = secp256k1.Point.BASE.multiplyAndAddUnsafe(P, t, _1n)
  if (!Q) throw new Error(INVALID_TWEAK_MESSAGE)
  return fromUint8Super(Q.toRawBytes(compressed), format)
}

/* ECDSA */

export async function ecdsaSignHash({
  hash,
  privateKey,
  extraEntropy = true,
  der = false,
  recovery = false,
  format,
  ...rest
}) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  assertUint8(hash, 32)
  assert(typeof der === 'boolean', '"der" should be boolean')
  assert(typeof recovery === 'boolean', '"recovery" should be boolean')
  if (extraEntropy !== true && extraEntropy !== null) assertUint8(extraEntropy, 32)
  // sign checks private key validity
  if (recovery) {
    const [sig, rc] = await secp256k1.sign(hash, privateKey, { der, extraEntropy, recovered: true })
    return { __proto__: null, signature: fromUint8Super(sig, format), recovery: rc }
  }
  const signature = await secp256k1.sign(hash, privateKey, { der, extraEntropy })
  return fromUint8Super(signature, format)
}

export function ecdsaSignHashSync({
  hash,
  privateKey,
  extraEntropy = true,
  der = false,
  recovery = false,
  format,
  ...rest
}) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  assertUint8(hash, 32)
  assert(typeof der === 'boolean', '"der" should be boolean')
  assert(typeof recovery === 'boolean', '"recovery" should be boolean')
  if (extraEntropy !== true && extraEntropy !== null) assertUint8(extraEntropy, 32)
  // signSync checks private key validity
  if (recovery) {
    const [sig, rc] = secp256k1.signSync(hash, privateKey, { der, extraEntropy, recovered: true })
    return { __proto__: null, signature: fromUint8Super(sig, format), recovery: rc }
  }
  const signature = secp256k1.signSync(hash, privateKey, { der, extraEntropy })
  return fromUint8Super(signature, format)
}

export const ecdsaVerifyHash = async (args) => ecdsaVerifyHashSync(args)
export function ecdsaVerifyHashSync({ signature, hash, publicKey, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8PublicKeyLength(publicKey)
  assert(publicKeyIsValid({ publicKey }), 'Invalid point')
  assertUint8(signature, 64)
  assertUint8(hash, 32)
  secp256k1.Signature.fromCompact(signature) // verify returns false on semantically invalid sigs, this throws instead
  // verify checks r and s validity (0 < * < n), also checks s <= n / 2 with strict: true (default), and returns false on that
  // signatures with high s (can be checked with Signature.fromHex().hasHighS()) do not throw, but return false here
  return secp256k1.verify(signature, hash, publicKey)
}

export async function ecdsaSignMessage({ message, ...rest }) {
  assertUint8AnySize(message)
  return ecdsaSignHash({ hash: await utils.sha256(message), ...rest })
}

export function ecdsaSignMessageSync({ message, ...rest }) {
  assertUint8AnySize(message)
  return ecdsaSignHashSync({ hash: utils.sha256Sync(message), ...rest })
}

export async function ecdsaVerifyMessage({ message, ...rest }) {
  assertUint8AnySize(message)
  return ecdsaVerifyHash({ hash: await utils.sha256(message), ...rest })
}

export function ecdsaVerifyMessageSync({ message, ...rest }) {
  assertUint8AnySize(message)
  return ecdsaVerifyHashSync({ hash: utils.sha256Sync(message), ...rest })
}

/* Schnorr */

// BIP-340 recommends passing 32 bytes of randomness to the signing function
// We do this by default, if impl wants to disable it for reproducible signatures e.g. for tests, it can override extraEntropy

// TODO: Schnorr signatures don't actually need the message to be 32-byte, perhaps we can lift that check

export async function schnorrSign({ data, privateKey, extraEntropy, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  assertUint8(data, 32)
  if (extraEntropy !== undefined) assertUint8(extraEntropy, 32)
  // checks private key validity
  const signature = await secp256k1.schnorr.sign(data, privateKey, extraEntropy) // extraEntropy is 32 bytes of csprng by default in noble
  return fromUint8Super(signature, format)
}

export function schnorrSignSync({ data, privateKey, extraEntropy, format, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(privateKey, 32)
  assertUint8(data, 32)
  if (extraEntropy !== undefined) assertUint8(extraEntropy, 32)
  // checks private key validity
  const signature = secp256k1.schnorr.signSync(data, privateKey, extraEntropy) // extraEntropy is 32 bytes of csprng by default in noble
  return fromUint8Super(signature, format)
}

export async function schnorrVerify({ signature, data, xOnly, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(xOnly, 32) // Only X
  assert(xOnlyIsValid({ xOnly }), 'Invalid point')
  assertUint8(signature, 64)
  assertUint8(data, 32)
  secp256k1.schnorr.Signature.fromHex(signature) // verify returns false on semantically invalid sigs, this throws instead
  return secp256k1.schnorr.verify(signature, data, xOnly)
}

export function schnorrVerifySync({ signature, data, xOnly, ...rest }) {
  assert(Object.keys(rest).length === 0, 'Unexpected extra options')
  assertUint8(xOnly, 32) // Only X
  assert(xOnlyIsValid({ xOnly }), 'Invalid point')
  assertUint8(signature, 64)
  assertUint8(data, 32)
  secp256k1.schnorr.Signature.fromHex(signature) // verify returns false on semantically invalid sigs, this throws instead
  return secp256k1.schnorr.verifySync(signature, data, xOnly)
}

/* Compatibility layer with tiny-secp256k1 v2 / bitcoinerlab-secp256k1, for bitcoinjs and ecpair */

// This is what ecpair expects from tweak API, and then rechecks the result and re-throws
// We do this only for the tweaks API
const throwTweakToNull = (f) => {
  try {
    return f()
  } catch (e) {
    if (e.message === 'Expected valid private scalar: 0 < scalar < curve.n') return null // publicKeyTweakMultiply can throw that
    if (e.message === INVALID_TWEAK_MESSAGE) return null
    throw e
  }
}

// We throw on invalid type and validate content
// tiny-secp256k1 returns false on invalid type
const throwIsValidToFalse = (f) => {
  try {
    return Boolean(f())
  } catch {
    return false
  }
}

export const tiny_secp256k1_compat = {
  isPoint: (publicKey) => throwIsValidToFalse(() => publicKeyIsValid({ publicKey })), // 33 or 65
  isPointCompressed: (publicKey) =>
    throwIsValidToFalse(() => publicKeyIsValid({ publicKey, compressed: true })), // 33
  isPrivate: (privateKey) => throwIsValidToFalse(() => privateKeyIsValid({ privateKey })),
  isXOnlyPoint: (xOnly) => throwIsValidToFalse(() => xOnlyIsValid({ xOnly })),
  pointFromScalar: (privateKey, compressed = true) =>
    privateKeyToPublicKey({ privateKey, compressed }),
  pointCompress: (publicKey, compressed = defaultCompressedValue(publicKey)) =>
    publicKeyConvert({ publicKey, compressed }), // this, despite its name, does not compress if second option is not specified
  pointAdd: (publicKey, tweakPoint, compressed) =>
    throwTweakToNull(() => publicKeyTweakAddPoint({ publicKey, tweakPoint, compressed })),
  pointAddScalar: (publicKey, tweak, compressed) =>
    throwTweakToNull(() => publicKeyTweakAddScalar({ publicKey, tweak, compressed })),
  pointMultiply: (publicKey, tweak, compressed) =>
    throwTweakToNull(() => publicKeyTweakMultiply({ publicKey, tweak, compressed })),
  privateAdd: (privateKey, tweak) =>
    throwTweakToNull(() => privateKeyTweakAdd({ privateKey, tweak })),
  privateSub: (privateKey, tweak) =>
    throwTweakToNull(() => privateKeyTweakSubtract({ privateKey, tweak })),
  privateNegate: (privateKey) => throwTweakToNull(() => privateKeyTweakNegate({ privateKey })),
  xOnlyPointAddTweak: (xOnly, tweak) =>
    throwTweakToNull(() => {
      const publicKey = xOnlyTweakAdd({ xOnly, tweak })
      return { parity: publicKey[0] % 2, xOnlyPubkey: publicKey.subarray(1) }
    }),
  signRecoverable: (hash, privateKey, extraEntropy = null) => {
    const result = ecdsaSignHashSync({ hash, privateKey, extraEntropy, recovery: true })
    return { signature: result.signature, recoveryId: result.recovery }
  },
  sign: (hash, privateKey, extraEntropy = null) =>
    ecdsaSignHashSync({ hash, privateKey, extraEntropy }),
  verify: (hash, publicKey, signature) => ecdsaVerifyHashSync({ hash, publicKey, signature }), // unlike tiny-secp256k1, we are always strict. this will cause false negatives but prevent malleability
  signSchnorr: (data, privateKey, extraEntropy) =>
    schnorrSignSync({ data, privateKey, extraEntropy }),
  verifySchnorr: (data, xOnly, signature) => schnorrVerifySync({ data, xOnly, signature }),
  xOnlyPointFromPoint: (publicKey) => publicKeyToX({ publicKey }),
  xOnlyPointFromScalar: (privateKey) =>
    publicKeyToX({ publicKey: privateKeyToPublicKey({ privateKey, compressed: true }) }),
}
