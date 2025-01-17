import { test, expect } from '@exodus/test/jest'
import crypto from 'node:crypto'
import * as secp256k1 from '../secp256k1.mjs'
import { hashSync } from '../hash.js'
import { invertSignature } from './util/secp256k1.mjs'

const makeDerPrivate = (privateKey, publicKey) =>
  Buffer.concat([
    Buffer.from('30740201010420', 'hex'),
    privateKey,
    Buffer.from('a00706052b8104000aa144034200', 'hex'),
    publicKey,
  ])

const makeDerPublic = (publicKey) =>
  Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex'), publicKey])

const getKeyPair = () => {
  const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' })
  const privateDer = keyPair.privateKey.export({ type: 'sec1', format: 'der' })
  const publicDer = keyPair.publicKey.export({ type: 'spki', format: 'der' })
  const privateKey = privateDer.subarray(7, 7 + 32)
  const publicKey = publicDer.subarray(23, 23 + 65)
  expect(privateDer).toEqual(makeDerPrivate(privateKey, publicKey))
  expect(publicDer).toEqual(makeDerPublic(publicKey))
  return { keyPair, privateDer, publicDer, privateKey, publicKey }
}

const signMessage = (message, privateKey) => {
  const signature = crypto.sign('SHA256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  expect(signature.length).toBe(64)
  return invertSignature(signature, true)
}
const verifyMessage = (signature, message, publicKey) => {
  return crypto.verify('SHA256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
}

test('secp256k1 matches OpenSSL in Node.js', () => {
  for (let i = 0; i < 20; i++) {
    const { privateKey, publicKey, keyPair } = getKeyPair()
    expect(
      secp256k1.privateKeyToPublicKey({ privateKey, compressed: false, format: 'buffer' })
    ).toEqual(publicKey)

    const data0 = crypto.randomBytes(Math.floor(256 * Math.random()))
    const hash0 = hashSync('sha256', data0)
    const sig0A = signMessage(data0, keyPair.privateKey)
    const sig0B = secp256k1.ecdsaSignHashSync({ hash: hash0, privateKey, format: 'buffer' })
    const sig0C = secp256k1.ecdsaSignMessageSync({ message: data0, privateKey, format: 'buffer' })

    const data1 = crypto.randomBytes(Math.floor(256 * Math.random()))
    const hash1 = hashSync('sha256', data1)
    const sig1A = signMessage(data1, keyPair.privateKey)
    const sig1B = secp256k1.ecdsaSignHashSync({ hash: hash1, privateKey, format: 'buffer' })
    const sig1C = secp256k1.ecdsaSignMessageSync({ message: data1, privateKey, format: 'buffer' })

    const checkBoth = (message, hash, signatures, valid) => {
      for (const signature of signatures) {
        expect(secp256k1.ecdsaVerifyHashSync({ hash, signature, publicKey })).toBe(valid)
        expect(secp256k1.ecdsaVerifyMessageSync({ message, signature, publicKey })).toBe(valid)
        expect(verifyMessage(signature, message, keyPair.publicKey)).toBe(valid)
      }
    }

    checkBoth(data0, hash0, [sig0A, sig0B, sig0C], true)
    checkBoth(data0, hash0, [sig1A, sig1B, sig1C], false)
    checkBoth(data1, hash1, [sig1A, sig1B, sig1C], true)
    checkBoth(data1, hash1, [sig0A, sig0B, sig0C], false)
  }
})
