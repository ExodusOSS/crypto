import { test, expect } from '@exodus/test/jest'
import { makeEntropy, ensure } from './util/curve25519.mjs'

test('curve25519 conversions', async () => {
  const entropy = makeEntropy()

  // edwardsToMontgomeryPublic
  // edwardsToMontgomeryPrivate
  // edwardsToPublic
  // montgomeryToPublic
  // getSharedSecretMontgomery
  // getSharedSecretEdwards
  for (let i = 0; i < entropy.length - 1; i++) {
    const [seed0, seed1] = [entropy[i], entropy[i + 1]]
    await ensure(async (s) => {
      const privateKeyED1 = Buffer.from(seed0)
      const privateKeyED2 = Buffer.from(seed1)
      const publicKeyED1 = await s.edwardsToPublic({ privateKey: privateKeyED1 })
      const publicKeyED2 = await s.edwardsToPublic({ privateKey: privateKeyED2 })
      const privateKeyX1 = await s.edwardsToMontgomeryPrivate({ privateKey: privateKeyED1 })
      const privateKeyX2 = await s.edwardsToMontgomeryPrivate({ privateKey: privateKeyED2 })
      const publicKeyX1 = await s.montgomeryToPublic({ privateKey: privateKeyX1 })
      const publicKeyX2 = await s.montgomeryToPublic({ privateKey: privateKeyX2 })
      expect(await s.edwardsToMontgomeryPublic({ publicKey: publicKeyED1 })).toStrictEqual(
        publicKeyX1
      )
      expect(await s.edwardsToMontgomeryPublic({ publicKey: publicKeyED2 })).toStrictEqual(
        publicKeyX2
      )
      const sharedSecret12 = await s.getSharedSecretMontgomery({
        privateKey: privateKeyX1,
        publicKey: publicKeyX2,
      })
      expect(
        await s.getSharedSecretEdwards({ privateKey: privateKeyED1, publicKey: publicKeyED2 })
      ).toStrictEqual(sharedSecret12)
      const sharedSecret21 = await s.getSharedSecretMontgomery({
        privateKey: privateKeyX2,
        publicKey: publicKeyX1,
      })
      expect(
        await s.getSharedSecretEdwards({ privateKey: privateKeyED2, publicKey: publicKeyED1 })
      ).toStrictEqual(sharedSecret21)
      expect(sharedSecret12).toStrictEqual(sharedSecret21)
      const invalidRaw = (seed) => seed.every((x) => x === 0) || seed.every((x) => x === 255)
      return {
        one: { privateKeyED1, publicKeyED1, privateKeyX1, publicKeyX1, sharedSecret12 },
        two: { privateKeyED2, publicKeyED2, privateKeyX2, publicKeyX2, sharedSecret21 },
        montRaw: [
          // Check non-normalized input as montgomery
          invalidRaw(seed0) ? null : await s.montgomeryToPublic({ privateKey: Buffer.from(seed0) }),
          invalidRaw(seed1) ? null : await s.montgomeryToPublic({ privateKey: Buffer.from(seed1) }),
        ],
      }
    })
  }
})
