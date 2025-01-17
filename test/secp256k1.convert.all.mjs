import { test, expect } from '@exodus/test/jest'
import { makeEntropy, ensure } from './util/secp256k1.mjs'

test('secp256k1 conversions and tweaks', async () => {
  const entropy = makeEntropy()

  // privateKeyIsValid
  // privateKeyTweakNegate
  // privateKeyTweakAdd
  // privateKeyTweakSubtract
  // privateKeyToPublicKey

  // publicKeyIsValid
  // publicKeyConvert
  // publicKeyToX
  // xOnlyIsValid

  // publicKeyTweakAddPoint
  // publicKeyTweakAddScalar
  // publicKeyTweakMultiply
  // xOnlyTweakAdd
  for (let i = 0; i < entropy.length - 1; i++) {
    const [seed0, seed1] = [entropy[i], entropy[i + 1]]
    const run = (s) => {
      const res = [{ seed0, seed1 }]

      // Part 1, private key might be invalid here
      const privateKey = new Uint8Array(seed0)
      res.push({ privateKey })
      const privateKeyValid = s.privateKeyIsValid({ privateKey })
      res.push({ privateKeyValid }) // must not be tampered during operations
      res.push({ privateKeyValidSeed1: s.privateKeyIsValid({ privateKey: seed1 }) })
      try {
        const negate = s.privateKeyTweakNegate({ privateKey })
        const negateValid = s.privateKeyIsValid({ privateKey: negate })
        res.push({ negate, negateValid })
      } catch {
        res.push({ negateThrew: true })
      }
      try {
        const add = s.privateKeyTweakAdd({ privateKey, tweak: seed1 })
        const addValid = s.privateKeyIsValid({ privateKey: add })
        res.push({ add, addValid })
      } catch {
        res.push({ addThrew: true })
      }
      try {
        const subtract = s.privateKeyTweakSubtract({ privateKey, tweak: seed1 })
        const subtractValid = s.privateKeyIsValid({ privateKey: subtract })
        res.push({ subtract, subtractValid })
      } catch {
        res.push({ subtractThrew: true })
      }
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
      expect(s.publicKeyIsValid({ publicKey })).toBe(true)
      expect(s.publicKeyIsValid({ publicKey, compressed: true })).toBe(true)
      expect(s.publicKeyIsValid({ publicKey, compressed: false })).toBe(false)
      const pubKeyFull = s.privateKeyToPublicKey({ privateKey, compressed: false })
      expect(s.publicKeyIsValid({ publicKey: pubKeyFull })).toBe(true)
      expect(s.publicKeyIsValid({ publicKey: pubKeyFull, compressed: true })).toBe(false)
      expect(s.publicKeyIsValid({ publicKey: pubKeyFull, compressed: false })).toBe(true)
      expect(publicKey).not.toEqual(pubKeyFull)
      expect(s.publicKeyConvert({ publicKey, compressed: true })).toEqual(publicKey)
      expect(s.publicKeyConvert({ publicKey, compressed: false })).toEqual(pubKeyFull)
      expect(s.publicKeyConvert({ publicKey: pubKeyFull, compressed: true })).toEqual(publicKey)
      expect(s.publicKeyConvert({ publicKey: pubKeyFull, compressed: false })).toEqual(pubKeyFull)
      const checkPub = (prefix, body) => {
        const pub = Buffer.concat([Buffer.from([prefix]), body])
        res.push({ pub, valid: s.publicKeyIsValid({ publicKey: pub }) })
      }
      for (let prefix = 0; prefix < 6; prefix++) {
        checkPub(prefix, seed0)
        checkPub(prefix, seed1)
        checkPub(prefix, Buffer.concat([seed0, seed1]))
      }
      const xOnly = s.publicKeyToX({ publicKey })
      res.push({ xOnly })
      expect(s.xOnlyIsValid({ xOnly })).toBe(true)
      res.push({ xOnlyIsValidSeed0: s.xOnlyIsValid({ xOnly: seed0 }) })
      res.push({ xOnlyIsValidSeed1: s.xOnlyIsValid({ xOnly: seed1 }) })

      // Part 3, public / xOnly tweaks
      try {
        const publicKeyTimes2 = s.publicKeyTweakAddPoint({ publicKey, tweakPoint: publicKey })
        res.push({ publicKeyTimes2 })
      } catch {
        res.push({ publicKeyTimes2Threw: true })
      }
      try {
        const publicKeySeed1 = s.privateKeyToPublicKey({ privateKey: seed1 })
        try {
          const publicKeyTweakAddPoint = s.publicKeyTweakAddPoint({
            publicKey,
            tweakPoint: publicKeySeed1,
          })
          res.push({ publicKeyTweakAddPoint })
        } catch {
          res.push({ publicKeyTweakAddPointThrew: true })
        }
      } catch {
        res.push({ publicKeySeed1Threw: true })
        expect(s.privateKeyIsValid({ privateKey: seed1 })).toBe(false)
      }
      try {
        const publicKeyTweakAddScalar = s.publicKeyTweakAddScalar({ publicKey, tweak: seed1 })
        res.push({ publicKeyTweakAddScalar })
      } catch (e) {
        res.push({ publicKeyTweakAddScalarThrew: true })
      }
      try {
        const publicKeyTweakMultiply = s.publicKeyTweakMultiply({ publicKey, tweak: seed1 })
        res.push({ publicKeyTweakMultiply })
      } catch {
        res.push({ publicKeyTweakMultiplyThrew: true })
      }
      try {
        const xOnlyTweakAdd = s.xOnlyTweakAdd({ xOnly, tweak: seed1 })
        res.push({ xOnlyTweakAdd })
      } catch {
        res.push({ xOnlyTweakAddThrew: true })
      }
      return res
    }

    await ensure(run, { skip: ['sync'] }) // no need to retest, sync/async makes difference only for sign/verify
  }
})
