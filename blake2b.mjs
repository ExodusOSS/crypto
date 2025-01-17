import { blake2b as blake_2b } from '@noble/hashes/blake2b'
import { hashWrap } from './utils/hash.mjs'

export const blake2b = hashWrap(blake_2b)
export const blake2bWithOptions = ({ size, ...rest }) => {
  if (Object.keys(rest).length !== 0) throw new Error('Unexpected options')
  if (size !== undefined && !Number.isSafeInteger(size)) throw new Error('Expected integer size')
  return hashWrap(blake_2b, { dkLen: size })
}
