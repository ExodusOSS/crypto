import { test, expect } from '@exodus/test/jest'
import { makeEntropy, ensure, corrupt } from './util/secp256k1.mjs'

test('secp256k1 sign/verify', async () => {
  const entropy = makeEntropy()

  // ecdsaSignHash
  // ecdsaVerifyHash
  // ecdsaSignHashSync (in alternate versions inside utils)
  // ecdsaVerifyHashSync (in alternate versions inside utils)
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
      const signature = await s.ecdsaSignHash({ hash: seed1, privateKey, extraEntropy: null })
      res.push({ signature })
      const signature0 = await s.ecdsaSignHash({ hash: seed1, privateKey, extraEntropy: null })
      const signature1 = await s.ecdsaSignHash({ hash: seed1, privateKey })
      const signature2 = await s.ecdsaSignHash({ hash: seed1, privateKey })
      expect(signature0).toEqual(signature)
      expect(signature1).not.toEqual(signature0)
      expect(signature2).not.toEqual(signature0)
      expect(signature2).not.toEqual(signature1)
      const verify = (sig) => s.ecdsaVerifyHash({ signature: sig, hash: seed1, publicKey })
      await expect(verify(new Uint8Array(64))).rejects.toThrow(/signature/i)
      await expect(verify(new Uint8Array(64).fill(255))).rejects.toThrow(/signature/i)
      for (const sig of [signature, signature1, signature2]) {
        expect(await verify(sig)).toBe(true)
        expect(await verify(corrupt(sig))).toBe(false) // this can't realistically make an element 0 or > n, so shouldn't throw
      }
      return res
    })
  }
})
