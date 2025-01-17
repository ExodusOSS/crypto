import { expect } from '@exodus/test/jest'
import secp256k1cryptocoinjs from 'secp256k1'
import secp256k1exodus from '@exodus/secp256k1'
// import * as bitcoinjs from '@bitcoin-js/tiny-secp256k1-asmjs'
import * as bitcoinerlab from '@exodus/bitcoinerlab-secp256k1'
import * as base from '../../secp256k1.mjs' // Async, might use webcrypto
import { randomBytes } from '../../randomBytes.js'

const assertNonZeroSignature = (signature) => {
  if (signature.subarray(0, 32).every((x) => x === 0)) throw new Error('Invalid signature')
  if (signature.subarray(32, 64).every((x) => x === 0)) throw new Error('Invalid signature')
}

const tweak0ToThrow = (f) => {
  const res = f()
  if (res.every((x) => x === 0)) throw new Error('Invalid tweak result')
  return res
}

const wrapCryptocoinJSInterface = (api) => {
  const c = (k) => {
    // secp256k1-node changes variables in-place and returns the same refs instead of operating on fresh copies
    // it also doesn't check key validity before applying a tweak to it
    if (!api.privateKeyVerify(k)) throw new Error('Invalid private key')
    return new Uint8Array(k)
  }
  expect(api.privateKeyTweakSubtract === undefined).toBe(true)
  expect(api.privateKeyTweakSub === undefined).toBe(true)
  return {
    privateKeyIsValid: ({ privateKey }) => api.privateKeyVerify(privateKey),
    privateKeyTweakNegate: ({ privateKey }) =>
      tweak0ToThrow(() => api.privateKeyNegate(c(privateKey))),
    privateKeyTweakAdd: ({ privateKey, tweak }) =>
      tweak0ToThrow(() => api.privateKeyTweakAdd(c(privateKey), tweak)),
    privateKeyTweakSubtract: base.privateKeyTweakSubtract, // not implemented in the lib
    privateKeyToPublicKey: ({ privateKey, compressed }) =>
      api.publicKeyCreate(privateKey, compressed),
    publicKeyIsValid: ({ publicKey, compressed }) => {
      if (!api.publicKeyVerify(publicKey)) return false
      if (!api.publicKeyVerify(api.publicKeyConvert(publicKey, false))) return false // ...
      // fail-open on a purpose, for testsuite only!
      if (compressed === false && publicKey.length === 33) return false
      if (compressed === true && publicKey.length === 65) return false
      return true
    },
    publicKeyConvert: ({ publicKey, compressed }) => api.publicKeyConvert(publicKey, compressed),
    publicKeyToX: base.publicKeyToX, // not implemented in the lib
    xOnlyIsValid: base.xOnlyIsValid, // not implemented in the lib
    publicKeyTweakAddPoint: base.publicKeyTweakAddPoint, // not implemented in the lib
    publicKeyTweakAddScalar: ({ publicKey, tweak, compressed }) =>
      api.publicKeyTweakAdd(new Uint8Array(publicKey), tweak, compressed),
    publicKeyTweakMultiply: ({ publicKey, tweak, compressed }) =>
      api.publicKeyTweakMul(new Uint8Array(publicKey), tweak, compressed),
    xOnlyTweakAdd: base.xOnlyTweakAdd, // not implemented in the lib
    ecdsaSignHash: base.ecdsaSignHash, // signatures mismatch & extra entropy not supported directly
    ecdsaVerifyHash: async ({ signature, hash, publicKey }) => {
      try {
        return api.ecdsaVerify(signature, hash, publicKey)
      } finally {
        assertNonZeroSignature(signature)
      }
    },
    schnorrSign: base.schnorrSign, // not implemented in the lib
    schnorrVerify: base.schnorrVerify, // not implemented in the lib
  }
}

const tweakNullToThrow = (f) => {
  const res = f()
  if (res === null) throw new Error('Invalid tweak result')
  return res
}

const wrapTinyInterface = (tiny) => ({
  privateKeyIsValid: ({ privateKey }) => tiny.isPrivate(privateKey),
  privateKeyTweakNegate: ({ privateKey }) => tiny.privateNegate(privateKey),
  privateKeyTweakAdd: ({ privateKey, tweak }) => tiny.privateAdd(privateKey, tweak),
  privateKeyTweakSubtract: ({ privateKey, tweak }) => tiny.privateSub(privateKey, tweak),
  privateKeyToPublicKey: ({ privateKey, compressed }) =>
    tiny.pointFromScalar(privateKey, compressed),
  publicKeyIsValid: ({ publicKey, compressed }) => {
    if (compressed === true) return tiny.isPointCompressed(publicKey)
    if (!tiny.isPoint(publicKey)) return false
    if (compressed === false) return !tiny.isPointCompressed(publicKey)
    return compressed === undefined
  },
  publicKeyConvert: ({ publicKey, compressed }) => tiny.pointCompress(publicKey, compressed),
  publicKeyToX: ({ publicKey }) => tiny.xOnlyPointFromPoint(publicKey),
  xOnlyIsValid: ({ xOnly }) => tiny.isXOnlyPoint(xOnly),
  publicKeyTweakAddPoint: ({ publicKey, tweakPoint }) =>
    tweakNullToThrow(() => tiny.pointAdd(publicKey, tweakPoint)),
  publicKeyTweakAddScalar: ({ publicKey, tweak }) =>
    tweakNullToThrow(() => tiny.pointAddScalar(publicKey, tweak)),
  publicKeyTweakMultiply: ({ publicKey, tweak }) =>
    tweakNullToThrow(() => tiny.pointMultiply(publicKey, tweak)),
  xOnlyTweakAdd: ({ xOnly, tweak }) =>
    tweakNullToThrow(() => {
      const { parity, xOnlyPubkey } = tiny.xOnlyPointAddTweak(xOnly, tweak)
      return new Uint8Array([parity ? 3 : 2, ...xOnlyPubkey])
    }),
  ecdsaSignHash: async ({ hash, privateKey, extraEntropy = true }) => {
    if (extraEntropy === true) extraEntropy = randomBytes(32) // eslint-disable-line no-param-reassign
    return tiny.sign(hash, privateKey, extraEntropy || undefined)
  },
  ecdsaVerifyHash: async ({ signature, hash, publicKey }) => {
    try {
      return tiny.verify(hash, publicKey, signature)
    } finally {
      assertNonZeroSignature(signature)
    }
  },
  schnorrSign: async ({ data, privateKey, extraEntropy = randomBytes(32) }) =>
    tiny.signSchnorr(data, privateKey, extraEntropy),
  schnorrVerify: async ({ signature, data, xOnly }) => {
    try {
      return tiny.verifySchnorr(data, xOnly, signature)
    } finally {
      assertNonZeroSignature(signature)
    }
  },
})

let alternate
async function getAlternate() {
  if (alternate) return alternate

  alternate = {
    sync: {
      ...base,
      ecdsaSignHash: async (args) => base.ecdsaSignHashSync(args),
      ecdsaVerifyHash: async (args) => base.ecdsaVerifyHashSync(args),
      ecdsaSignMessage: async (args) => base.ecdsaSignMessageSync(args),
      ecdsaVerifyMessage: async (args) => base.ecdsaVerifyMessageSync(args),
      schnorrSign: async (args) => base.schnorrSignSync(args),
      schnorrVerify: async (args) => base.schnorrVerifySync(args),
    },
    secp256k1cryptocoinjs: wrapCryptocoinJSInterface(secp256k1cryptocoinjs),
    secp256k1exodus: wrapCryptocoinJSInterface(secp256k1exodus),
    tiny_secp256k1_compat: wrapTinyInterface(base.tiny_secp256k1_compat),
    bitcoinerlab: wrapTinyInterface(bitcoinerlab),
    // bitcoinjs: wrapTinyInterface(bitcoinjs), // slow, but works
  }

  if (globalThis.WebAssembly !== undefined && process.env.EXODUS_TEST_ENVIRONMENT !== 'bundle') {
    // Importing tiny-secp256k1 throws without WebAssembly support (e.g. on Hermes)
    alternate.tiny_secp256k1 = wrapTinyInterface(await import('tiny-secp256k1'))
  }

  return alternate
}

export async function ensure(fn, { skip = [] } = {}) {
  const res = await fn(base)
  // console.log(res)
  for (const [name, impl] of Object.entries(await getAlternate())) {
    if (skip.includes(name)) continue
    expect(await fn(impl)).toStrictEqual(res)
  }
}

export function makeEntropy() {
  const entropy = []

  // to catch normalization issues
  for (const byte of [0, 253, 255]) entropy.push(Buffer.alloc(32, byte))
  entropy.push(Buffer.concat([Buffer.alloc(31, 255), Buffer.alloc(1, 254)]))
  entropy.push(Buffer.concat([Buffer.alloc(1, 254), Buffer.alloc(31, 254)]))
  entropy.push(Buffer.concat([Buffer.alloc(31, 0), Buffer.alloc(1, 1)]))
  entropy.push(Buffer.concat([Buffer.alloc(1, 1), Buffer.alloc(31, 0)]))

  // Random input
  for (let i = 0; i < 10; i++) entropy.push(randomBytes(32))

  entropy.push(Buffer.alloc(32)) // for tweaks / args to be empty

  return entropy
}

export function corrupt(arr) {
  const corrupted = new Uint8Array(arr)
  if (corrupted.length === 0) throw new Error('Can not corrupt a zero-length array')
  const byteToCorrupt = Math.floor(Math.random() * corrupted.length)
  corrupted[byteToCorrupt] = corrupted[byteToCorrupt] + 1
  return corrupted
}

const N = 2n ** 256n - 0x14551231950b75fc4402da1732fc9bebfn // === @noble/secp256k1.CURVE.n
export function invertSignature(signature, normalizeOnly = true) {
  const [R, S] = [signature.subarray(0, 32), signature.subarray(32, 64)]
  const s = BigInt(`0x${Buffer.from(S).toString('hex')}`)
  if (normalizeOnly && s * 2n <= N) return signature // it was canonical
  const altS = Buffer.from((N - s).toString(16).padStart(64, '0'), 'hex') // normalize otherwise
  return Buffer.concat([R, altS])
}
