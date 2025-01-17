import { test, expect } from '@exodus/test/jest'
import * as secp256k1 from '../secp256k1.mjs'
import { hashSync } from '../hash.js'
import { randomBytes } from '../randomBytes.js'

const check = async (publicKey, message, hash, signatures, valid) => {
  for (const signature of signatures) {
    expect(secp256k1.ecdsaVerifyHashSync({ hash, signature, publicKey })).toBe(valid)
    expect(secp256k1.ecdsaVerifyMessageSync({ message, signature, publicKey })).toBe(valid)
    expect(await secp256k1.ecdsaVerifyHash({ hash, signature, publicKey })).toBe(valid)
    expect(await secp256k1.ecdsaVerifyMessage({ message, signature, publicKey })).toBe(valid)
  }
}

const sig2der = (sig) => {
  const arr2der = (input) => {
    const arr = [...input]
    while (arr[0] === 0) arr.shift()
    if (arr[0] >= 0x80) arr.unshift(0)
    return [2, arr.length, ...arr]
  }
  const r = arr2der(sig.subarray(0, 32))
  const s = arr2der(sig.subarray(32))
  return new Uint8Array([48, r.length + s.length, ...r, ...s])
}

test('secp256k1 message signing matches with hash singin of message hashes', async () => {
  for (let i = 0; i < 5; i++) {
    const privateKey = randomBytes(32)
    const publicKey = secp256k1.privateKeyToPublicKey({ privateKey })

    const m0 = randomBytes(1 + Math.floor(256 * Math.random()))
    const hash0 = hashSync('sha256', m0)
    const sig0A = secp256k1.ecdsaSignHashSync({ hash: hash0, privateKey, extraEntropy: null })
    const sig0A0 = secp256k1.ecdsaSignMessageSync({ message: m0, privateKey, extraEntropy: null })
    const sig0A1 = await secp256k1.ecdsaSignHash({ hash: hash0, privateKey, extraEntropy: null })
    const sig0A2 = await secp256k1.ecdsaSignMessage({ message: m0, privateKey, extraEntropy: null })
    const sig0B = secp256k1.ecdsaSignHashSync({ hash: hash0, privateKey })
    const sig0C = secp256k1.ecdsaSignMessageSync({ message: m0, privateKey })
    expect(sig0A0).toEqual(sig0A)
    expect(sig0A1).toEqual(sig0A)
    expect(sig0A2).toEqual(sig0A)
    expect(sig0B).not.toEqual(sig0A)
    expect(sig0C).not.toEqual(sig0A)
    expect(sig0C).not.toEqual(sig0B)
    expect(
      await secp256k1.ecdsaSignMessage({
        message: m0,
        privateKey,
        der: true,
        extraEntropy: null,
      })
    ).toEqual(sig2der(sig0A))

    const sig0R = secp256k1.ecdsaSignHashSync({
      hash: hash0,
      privateKey,
      extraEntropy: null,
      recovery: true,
    })
    expect(
      await secp256k1.ecdsaSignMessage({
        message: m0,
        privateKey,
        extraEntropy: null,
        recovery: true,
      })
    ).toEqual(sig0R)
    expect(sig0R.signature).toEqual(sig0A)
    expect([0, 1].includes(sig0R.recovery)).toBe(true)

    const m1 = randomBytes(1 + Math.floor(256 * Math.random()))
    const hash1 = hashSync('sha256', m1)
    const sig1A = secp256k1.ecdsaSignHashSync({ hash: hash1, privateKey, extraEntropy: null })
    const sig1A0 = secp256k1.ecdsaSignMessageSync({ message: m1, privateKey, extraEntropy: null })
    const sig1A1 = await secp256k1.ecdsaSignHash({ hash: hash1, privateKey, extraEntropy: null })
    const sig1A2 = await secp256k1.ecdsaSignMessage({ message: m1, privateKey, extraEntropy: null })
    const sig1B = secp256k1.ecdsaSignHashSync({ hash: hash1, privateKey })
    const sig1C = secp256k1.ecdsaSignMessageSync({ message: m1, privateKey })
    expect(sig1A0).toEqual(sig1A)
    expect(sig1A1).toEqual(sig1A)
    expect(sig1A2).toEqual(sig1A)
    expect(sig1B).not.toEqual(sig1A)
    expect(sig1C).not.toEqual(sig1A)
    expect(sig1C).not.toEqual(sig1B)
    expect(
      await secp256k1.ecdsaSignMessage({
        message: m1,
        privateKey,
        der: true,
        extraEntropy: null,
      })
    ).toEqual(sig2der(sig1A))

    await check(publicKey, m0, hash0, [sig0A, sig0B, sig0C], true)
    await check(publicKey, m0, hash0, [sig1A, sig1B, sig1C], false)
    await check(publicKey, m1, hash1, [sig1A, sig1B, sig1C], true)
    await check(publicKey, m1, hash1, [sig0A, sig0B, sig0C], false)

    const sig1R = secp256k1.ecdsaSignHashSync({
      hash: hash1,
      privateKey,
      extraEntropy: null,
      recovery: true,
    })
    expect(
      await secp256k1.ecdsaSignMessage({
        message: m1,
        privateKey,
        extraEntropy: null,
        recovery: true,
      })
    ).toEqual(sig1R)
    expect(sig1R.signature).toEqual(sig1A)
    expect([0, 1].includes(sig1R.recovery)).toBe(true)
  }
})
