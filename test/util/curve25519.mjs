import sodiumPackage from '@exodus/sodium-crypto'
import { expect } from '@exodus/test/jest'
import * as curves from '@noble/curves/ed25519'
import * as ed25519 from '@noble/ed25519'
import * as sed25519 from '@stablelib/ed25519'
import * as sx25519 from '@stablelib/x25519'
import elliptic from 'elliptic'
import nacl from 'tweetnacl'
import * as base from '../../curve25519.mjs' // Async, might use webcrypto
import { randomBytes } from '../../randomBytes.js'

const B = (...args) => Buffer.from(...args) // compactness
const U = (...args) => Uint8Array.from(B(...args)) // compactness
const concat = (...args) => Uint8Array.from(Buffer.concat(args))

const ecEddsa = new elliptic.eddsa('ed25519') // eslint-disable-line new-cap
const ecCurve = new elliptic.ec('curve25519') // eslint-disable-line new-cap
const ecCurveKeyFromPrivate = (privateKey) => {
  // See https://github.com/indutny/elliptic/issues/98#issuecomment-238155817
  // 'elliptic' Montgomery keys are reversed and need to be normalized manually
  const eprivBuf = B(privateKey).reverse()
  eprivBuf[31] &= 248
  eprivBuf[0] &= 127
  eprivBuf[0] |= 64
  return ecCurve.keyFromPrivate(eprivBuf)
}

async function signOpen(impl, { signed, publicKey }) {
  const signature = signed.subarray(0, 64)
  const message = signed.subarray(64)
  const valid = await impl.verifyDetached({ message, signature, publicKey })
  if (!valid) throw new Error('incorrect signature for the given public key')
  return Uint8Array.from(message)
}

const alternate = {
  sync: {
    edwardsToMontgomeryPublic: base.edwardsToMontgomeryPublicSync,
    edwardsToMontgomeryPrivate: base.edwardsToMontgomeryPrivateSync,
    edwardsToPublic: base.edwardsToPublicSync,
    montgomeryToPublic: base.montgomeryToPublicSync,
    signDetached: base.signDetachedSync,
    verifyDetached: base.verifyDetachedSync,
    signAttached: base.signAttachedSync,
    signOpen: base.signOpenSync,
    getSharedSecretMontgomery: base.getSharedSecretMontgomerySync,
    getSharedSecretEdwards: base.getSharedSecretEdwardsSync,
  },
  nobleEd25519Async: {
    edwardsToMontgomeryPublic: async ({ publicKey }) => ed25519.Point.fromHex(publicKey).toX25519(),
    edwardsToMontgomeryPrivate: async ({ privateKey }) =>
      (await ed25519.utils.getExtendedPublicKey(privateKey)).head,
    edwardsToPublic: async ({ privateKey }) => ed25519.getPublicKey(privateKey),
    montgomeryToPublic: async ({ privateKey }) => ed25519.curve25519.scalarMultBase(privateKey),
    signDetached: async ({ message, privateKey }) => ed25519.sign(message, privateKey),
    verifyDetached: async ({ signature, message, publicKey }) =>
      ed25519.verify(signature, message, publicKey).catch(() => false),
    signAttached: async ({ message, ...r }) =>
      concat(await alternate.nobleEd25519Async.signDetached({ message, ...r }), message),
    signOpen: (args) => signOpen(alternate.nobleEd25519Async, args),
    getSharedSecretMontgomery: async ({ privateKey, publicKey }) =>
      ed25519.curve25519.scalarMult(privateKey, publicKey),
    getSharedSecretEdwards: async ({ privateKey, publicKey }) =>
      ed25519.getSharedSecret(privateKey, publicKey),
  },
  nobleCurves: {
    edwardsToMontgomeryPublic: ({ publicKey }) => curves.edwardsToMontgomeryPub(publicKey),
    edwardsToMontgomeryPrivate: ({ privateKey }) => curves.edwardsToMontgomeryPriv(privateKey),
    edwardsToPublic: ({ privateKey }) => curves.ed25519.getPublicKey(privateKey),
    montgomeryToPublic: ({ privateKey }) => curves.x25519.getPublicKey(privateKey),
    signDetached: ({ message, privateKey }) => curves.ed25519.sign(message, privateKey),
    verifyDetached: ({ signature, message, publicKey }) =>
      curves.ed25519.verify(signature, message, publicKey),
    signAttached: ({ message, ...r }) =>
      concat(alternate.nobleCurves.signDetached({ message, ...r }), message),
    signOpen: (args) => signOpen(alternate.nobleCurves, args),
    getSharedSecretMontgomery: ({ privateKey, publicKey }) =>
      curves.x25519.getSharedSecret(privateKey, publicKey),
    getSharedSecretEdwards: ({ privateKey, publicKey }) => {
      const privateKeyX = curves.edwardsToMontgomeryPriv(privateKey)
      const publicKeyX = curves.edwardsToMontgomeryPub(publicKey)
      return curves.x25519.getSharedSecret(privateKeyX, publicKeyX)
    },
  },
  stablelib: {
    edwardsToMontgomeryPublic: ({ publicKey }) => sed25519.convertPublicKeyToX25519(publicKey),
    edwardsToMontgomeryPrivate: ({ privateKey }) => sed25519.convertSecretKeyToX25519(privateKey),
    edwardsToPublic: ({ privateKey }) => sed25519.generateKeyPairFromSeed(privateKey).publicKey,
    montgomeryToPublic: ({ privateKey }) => sx25519.generateKeyPairFromSeed(privateKey).publicKey,
    signDetached: ({ message, privateKey }) =>
      sed25519.sign(sed25519.generateKeyPairFromSeed(privateKey).secretKey, message),
    verifyDetached: ({ signature, message, publicKey }) =>
      sed25519.verify(publicKey, message, signature),
    signAttached: ({ message, ...r }) =>
      concat(alternate.stablelib.signDetached({ message, ...r }), message),
    signOpen: (args) => signOpen(alternate.stablelib, args),
    getSharedSecretMontgomery: ({ privateKey, publicKey }) =>
      sx25519.sharedKey(privateKey, publicKey),
    getSharedSecretEdwards: ({ privateKey, publicKey }) => {
      const privateKeyX = sed25519.convertSecretKeyToX25519(privateKey)
      const publicKeyX = sed25519.convertPublicKeyToX25519(publicKey)
      return curves.x25519.getSharedSecret(privateKeyX, publicKeyX)
    },
  },
  elliptic: {
    edwardsToPublic: ({ privateKey }) => U(ecEddsa.keyFromSecret(privateKey).getPublic()),
    montgomeryToPublic: ({ privateKey }) => {
      // https://github.com/indutny/elliptic/issues/98#issuecomment-238155817
      const key = ecCurveKeyFromPrivate(privateKey)
      return U(key.getPublic().encode()).reverse()
    },
    signDetached: ({ message, privateKey }) => {
      const key = ecEddsa.keyFromSecret(privateKey)
      return U(key.sign(message).toBytes())
    },
    verifyDetached: ({ signature, message, publicKey }) => {
      try {
        const key = ecEddsa.keyFromPublic([...publicKey]) // If not an array just assigns it to key._pubBytes and breaks later
        return key.verify(message, [...signature]) // Only accepts arrays or strings as raw signatures
      } catch {
        return false // fails on invalid signatures
      }
    },
    signAttached: ({ message, ...r }) =>
      concat(alternate.elliptic.signDetached({ message, ...r }), message),
    signOpen: (args) => signOpen(alternate.elliptic, args),
    getSharedSecretMontgomery: ({ privateKey, publicKey }) => {
      const key = ecCurveKeyFromPrivate(privateKey)
      const keyPub = ecCurve.keyFromPublic([...publicKey].reverse()).getPublic()
      return U(key.derive(keyPub).toString(16, 64), 'hex').reverse()
    },
    // Not present in elliptic
    edwardsToMontgomeryPublic: base.edwardsToMontgomeryPublic,
    edwardsToMontgomeryPrivate: base.edwardsToMontgomeryPrivate,
    getSharedSecretEdwards: base.getSharedSecretEdwards,
  },
  nacl: {
    edwardsToPublic: ({ privateKey }) => {
      const { secretKey, publicKey } = nacl.sign.keyPair.fromSeed(privateKey)
      expect(secretKey).toStrictEqual(concat(privateKey, publicKey)) // same key but priv:pub
      return publicKey
    },
    montgomeryToPublic: ({ privateKey }) => nacl.box.keyPair.fromSecretKey(privateKey).publicKey,
    signDetached: ({ message, privateKey }) => {
      const { secretKey, publicKey } = nacl.sign.keyPair.fromSeed(privateKey)
      expect(secretKey).toStrictEqual(concat(privateKey, publicKey)) // same key but priv:pub
      return nacl.sign.detached(message, secretKey)
    },
    verifyDetached: ({ message, signature, publicKey }) => {
      return nacl.sign.detached.verify(message, signature, publicKey)
    },
    signAttached: ({ message, privateKey }) => {
      const { secretKey, publicKey } = nacl.sign.keyPair.fromSeed(privateKey)
      expect(secretKey).toStrictEqual(concat(privateKey, publicKey)) // same key but priv:pub
      return nacl.sign(message, secretKey)
    },
    signOpen: ({ signed, publicKey }) => {
      const res = nacl.sign.open(signed, publicKey)
      if (!res) throw new Error('incorrect signature for the given public key')
      return res
    },
    // Not present in tweetnacl
    edwardsToMontgomeryPublic: base.edwardsToMontgomeryPublic,
    edwardsToMontgomeryPrivate: base.edwardsToMontgomeryPrivate,
    getSharedSecretMontgomery: base.getSharedSecretMontgomery, // nacl.box.before is wrapped in hsalsa20
    getSharedSecretEdwards: base.getSharedSecretEdwards,
  },
  sodiumPackage: {
    edwardsToMontgomeryPublic: async ({ publicKey }) =>
      U(await sodiumPackage.convertPublicKeyToX25519(publicKey)),
    edwardsToMontgomeryPrivate: async ({ privateKey: key }) => {
      const { privateKey, publicKey } = await sodiumPackage.genSignKeyPair(key)
      expect(U(privateKey)).toStrictEqual(concat(key, publicKey)) // same key but priv:pub
      const privateKeyX = await sodiumPackage.convertPrivateKeyToX25519(privateKey)
      return U(privateKeyX)
    },
    edwardsToPublic: async ({ privateKey: key }) => {
      const { privateKey, publicKey } = await sodiumPackage.genSignKeyPair(key)
      expect(U(privateKey)).toStrictEqual(concat(key, publicKey)) // same key but priv:pub
      return U(publicKey)
    },
    signDetached: async ({ message, privateKey: key }) => {
      const { privateKey, publicKey } = await sodiumPackage.genSignKeyPair(key)
      expect(U(privateKey)).toStrictEqual(concat(key, publicKey)) // same key but priv:pub
      return U(await sodiumPackage.signDetached({ message, privateKey })) // async
    },
    verifyDetached: ({ signature: sig, ...rest }) => sodiumPackage.verifyDetached({ sig, ...rest }),
    signAttached: async ({ message, privateKey: key }) => {
      const { privateKey, publicKey } = await sodiumPackage.genSignKeyPair(key)
      expect(U(privateKey)).toStrictEqual(concat(key, publicKey)) // same key but priv:pub
      return U(await sodiumPackage.sign({ message, privateKey })) // async
    },
    signOpen: async ({ signed, publicKey }) =>
      U(await sodiumPackage.signOpen({ signed, publicKey })),
    // Not present in @exodus/sodium-crypto
    montgomeryToPublic: base.montgomeryToPublic,
    getSharedSecretMontgomery: base.getSharedSecretMontgomery,
    getSharedSecretEdwards: base.getSharedSecretEdwards,
  },
}

// Skip sodium on Hermes, it works but Hermes is slow as hell with it
if (process.env.EXODUS_TEST_PLATFORM === 'hermes') delete alternate.sodiumPackage

export async function ensure(fn) {
  const res = await fn(base)
  for (const [, impl] of Object.entries(alternate)) expect(await fn(impl)).toStrictEqual(res)
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

  return entropy
}
