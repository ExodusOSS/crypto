import '@exodus/patch-broken-hermes-typed-arrays' // for Hermes tests
import sodiumReal from '@exodus/sodium-crypto'
import * as sodiumMain from '../sodium.mjs'
import { randomBytes } from '../randomBytes.js'
import * as sodiumCurves from './util/sodium.curves.mjs'

import { test, expect } from '@exodus/test/jest'

const compare = async (base, ...impls) => {
  const ensure = async (fn) => {
    const res = await fn(base)
    for (const impl of impls) expect(await fn(impl)).toEqual(res)
  }

  const runChecks = async (entropy) => {
    // convertPrivateKeyToX25519
    await ensure((s) => s.convertPrivateKeyToX25519(entropy.subarray(0, 64)))
    await ensure((s) => s.convertPrivateKeyToX25519(entropy.subarray(32, 96))) // overlap

    // genSignKeyPair
    // genBoxKeyPair
    // getSodiumKeysFromSeed
    // convertPublicKeyToX25519
    for (let i = 0; i * 32 < entropy.length; i++) {
      const seed = entropy.subarray(32 * i, 32 * (i + 1))
      await ensure(async (s) => {
        const sign = await s.genSignKeyPair(seed)
        const box = await s.genBoxKeyPair(seed)
        const keys = await s.getSodiumKeysFromSeed(seed)
        const publicKeyX = await s.convertPublicKeyToX25519(sign.publicKey)
        expect(keys.sign).toEqual(sign)
        expect(keys.box.publicKey).toEqual(box.publicKey)
        expect(keys.box.privateKey).toEqual(box.privateKey)
        expect(Buffer.from(publicKeyX)).toEqual(box.publicKey)
        return { sign, box, keys, publicKeyX }
      })
    }

    // signDetached
    // verifyDetached
    await ensure(async (s) => {
      const { publicKey, privateKey } = await s.genSignKeyPair(entropy.subarray(0, 32))
      const message = entropy.subarray(32, 64)
      const sig = await s.signDetached({ message, privateKey })
      const ver = await s.verifyDetached({ message, sig, publicKey })
      const fail = await s.verifyDetached({ message: Buffer.from('invalid'), sig, publicKey })
      expect(ver).toBe(true)
      expect(fail).toBe(false)
      return { sig, ver, fail }
    })

    // sign
    // signOpen
    await ensure(async (s) => {
      const { publicKey, privateKey } = await s.genSignKeyPair(entropy.subarray(0, 32))
      const message = entropy.subarray(32, 64)
      const signed = await s.sign({ message, privateKey })
      const opened = await s.signOpen({ signed, publicKey })
      expect(opened).toEqual(message)
      const error = new Error('incorrect signature for the given public key')
      const invalid = Buffer.concat([signed, Buffer.alloc(1)])
      await expect(s.signOpen({ signed: invalid, publicKey })).rejects.toEqual(error)
      return { signed, opened }
    })
  }

  const entropySize = 32 * 3
  for (const byte of [0, 100, 255]) await runChecks(Buffer.alloc(entropySize, byte))
  for (let i = 0; i < 10; i++) await runChecks(randomBytes(entropySize))
}

test('main', async () => {
  await compare(sodiumReal, sodiumMain, sodiumCurves)
})
