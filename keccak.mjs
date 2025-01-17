import { keccak_224, keccak_256, keccak_384, keccak_512 } from '@noble/hashes/sha3'
import { hashWrap } from './utils/hash.mjs'

export const keccak224 = hashWrap(keccak_224)
export const keccak256 = hashWrap(keccak_256)
export const keccak384 = hashWrap(keccak_384)
export const keccak512 = hashWrap(keccak_512)
