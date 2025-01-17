import { test, expect } from '@exodus/test/jest'
import { makeEntropy, ensure, corrupt } from './util/secp256k1.mjs'

test('secp256k1 schnorr sign/verify', async () => {
  const entropy = makeEntropy()

  // schnorrSign
  // schnorrVerify
  // schnorrSignSync (in alternate versions inside utils)
  // schnorrVerifySync (in alternate versions inside utils)
  for (let i = 0; i < entropy.length - 1; i++) {
    const [seed0, seed1] = [entropy[i], entropy[i + 1]]
    await ensure(async (s) => {
      const res = [{ seed0, seed1 }]

      // Part 1, private key might be invalid here
      const privateKey = new Uint8Array(seed0)
      const privateKeyValid = s.privateKeyIsValid({ privateKey })
      res.push({ privateKeyValid })
      let publicKey
      try {
        publicKey = s.privateKeyToPublicKey({ privateKey })
        res.push({ publicKey })
      } catch {
        res.push({ publicKeyThrew: true })
        expect(privateKeyValid).toBe(false)
        return res // nothing to do anymore, return early
      }

      // Part 2, only on valid private keys
      expect(privateKeyValid).toBe(true) // can reach here only with a valid key
      const xOnly = s.publicKeyToX({ publicKey })
      res.push({ xOnly })
      const empty32 = new Uint8Array(32)
      const signature = await s.schnorrSign({ data: seed1, privateKey, extraEntropy: empty32 })
      res.push({ signature })
      const signature0 = await s.schnorrSign({ data: seed1, privateKey, extraEntropy: empty32 })
      const signature1 = await s.schnorrSign({ data: seed1, privateKey })
      const signature2 = await s.schnorrSign({ data: seed1, privateKey })
      expect(signature0).toEqual(signature)
      expect(signature1).not.toEqual(signature0)
      expect(signature2).not.toEqual(signature0)
      expect(signature2).not.toEqual(signature1)
      const verify = (sig) => s.schnorrVerify({ signature: sig, data: seed1, xOnly })
      await expect(verify(new Uint8Array(64))).rejects.toThrow(/signature/i)
      await expect(verify(new Uint8Array(64).fill(255))).rejects.toThrow(/signature/i)
      for (const sig of [signature, signature1, signature2]) {
        expect(await verify(sig)).toBe(true)
        expect(await verify(corrupt(sig))).toBe(false)
      }
      return res
    })
  }
})
