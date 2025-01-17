import { test, expect } from '@exodus/test/jest'
import { makeEntropy, ensure } from './util/curve25519.mjs'

test('curve25519 sign/verify', async () => {
  const entropy = makeEntropy()

  // signDetached
  // verifyDetached
  // signAttached
  // signOpen
  for (let i = 0; i < entropy.length - 1; i++) {
    const [seed0, seed1] = [entropy[i], entropy[i + 1]]
    await ensure(async (s) => {
      const privateKey = Buffer.from(seed0)
      const publicKey = await s.edwardsToPublic({ privateKey })
      const message = Buffer.from(seed1)
      const signature = await s.signDetached({ message, privateKey })
      const signed = await s.signAttached({ message, privateKey })
      expect(signed).toStrictEqual(Uint8Array.from(Buffer.concat([signature, message])))
      const valid = await s.verifyDetached({ message, signature, publicKey })
      expect(valid).toBe(true)
      const invalid = await s.verifyDetached({
        message: Buffer.from('invalid'),
        signature,
        publicKey,
      })
      expect(invalid).toBe(false)
      const corruptedSignature = Buffer.from(signature)
      const byteToCorrupt = Math.floor(Math.random() * corruptedSignature.length)
      corruptedSignature[byteToCorrupt] = corruptedSignature[byteToCorrupt] + 1
      const corrupted = await s.verifyDetached({
        message,
        signature: corruptedSignature,
        publicKey,
      })
      expect(corrupted).toBe(false)
      const opened = await s.signOpen({ signed, publicKey })
      expect(opened).toStrictEqual(Uint8Array.from(message))
      const withExtraUnsignedBytes = Buffer.concat([signed, Buffer.alloc(1)])
      const shouldReject = async () => s.signOpen({ signed: withExtraUnsignedBytes, publicKey })
      const error = new Error('incorrect signature for the given public key')
      await expect(shouldReject()).rejects.toStrictEqual(error)
      return {
        keys: { privateKey, publicKey },
        valid: { message, signature, signed, valid, opened },
        invalid: { invalid, corrupted },
      }
    })
  }
})
