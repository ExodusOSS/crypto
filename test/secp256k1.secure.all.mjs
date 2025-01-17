import { beforeAll, describe, test, expect } from '@exodus/test/jest'
import * as secp256k1 from '../secp256k1.mjs'
import { randomBytes } from '../randomBytes.js'
import { invertSignature } from './util/secp256k1.mjs'

describe('secp256k1 secure defaults', async () => {
  let privateKey

  beforeAll(() => {
    while (!privateKey || !secp256k1.privateKeyIsValid({ privateKey })) {
      privateKey = randomBytes(32)
    }
  })

  test('publicKeyToX does a proper copy', async () => {
    const publicKey = secp256k1.privateKeyToPublicKey({ privateKey, format: 'buffer' })
    const xOnly = secp256k1.publicKeyToX({ publicKey, format: 'buffer' })
    const xOnlyHex = secp256k1.publicKeyToX({ publicKey, format: 'hex' })
    expect(xOnly.toString('hex')).toBe(xOnlyHex)
    xOnly.fill(0)
    expect(xOnly.toString('hex')).not.toBe(xOnlyHex)
    expect(secp256k1.publicKeyToX({ publicKey, format: 'hex' })).toBe(xOnlyHex)
    const publicKeyHex = secp256k1.privateKeyToPublicKey({ privateKey, format: 'hex' })
    expect(publicKeyHex).toBe(publicKey.toString('hex'))
  })

  test('ecdsa', async () => {
    const publicKey = secp256k1.privateKeyToPublicKey({ privateKey })
    const hash = randomBytes(32)
    const signature = await secp256k1.ecdsaSignHash({ hash, privateKey, extraEntropy: null })
    const signature0 = await secp256k1.ecdsaSignHash({ hash, privateKey, extraEntropy: null })
    const signature1 = await secp256k1.ecdsaSignHash({ hash, privateKey })
    const signature2 = await secp256k1.ecdsaSignHash({ hash, privateKey })
    expect(signature0).toEqual(signature)
    expect(signature1).not.toEqual(signature0)
    expect(signature2).not.toEqual(signature0)
    expect(signature2).not.toEqual(signature1)
    const verify = (sig) => secp256k1.ecdsaVerifyHash({ signature: sig, hash, publicKey })
    for (const sig of [signature, signature1, signature2]) {
      expect(await verify(sig)).toBe(true)
      expect(invertSignature(sig, true)).toEqual(sig)
      expect(await verify(invertSignature(sig, false))).toBe(false)
    }
  })

  test('schnorr', async () => {
    const publicKey = secp256k1.privateKeyToPublicKey({ privateKey })
    const xOnly = secp256k1.publicKeyToX({ publicKey })
    const data = randomBytes(32)
    const zeros = new Uint8Array(32)
    const signature = await secp256k1.schnorrSign({ data, privateKey, extraEntropy: zeros })
    const signature0 = await secp256k1.schnorrSign({ data, privateKey, extraEntropy: zeros })
    const signature1 = await secp256k1.schnorrSign({ data, privateKey })
    const signature2 = await secp256k1.schnorrSign({ data, privateKey })
    expect(signature0).toEqual(signature)
    expect(signature1).not.toEqual(signature0)
    expect(signature2).not.toEqual(signature0)
    expect(signature2).not.toEqual(signature1)
    const verify = (sig) => secp256k1.schnorrVerify({ signature: sig, data, xOnly })
    for (const sig of [signature, signature1, signature2]) {
      expect(await verify(sig)).toBe(true)
    }
  })
})
