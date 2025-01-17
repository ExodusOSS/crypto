import { Buffer } from 'buffer'

export function fromHex(data) {
  return new Uint8Array(Buffer.from(data, 'hex'))
}

export function toHex(data) {
  return Buffer.from(data).toString('hex')
}

// We expect different errors
export function makeErrorRegex(exception) {
  if (exception === 'Expected Tweak') return /Tweak is malformed/iu
  if (exception === 'Expected Private') return /Expected private key/iu
  if (exception === 'Expected Point') return /(Invalid point|Point is not on( elliptic)? curve)/iu
  if (exception === 'Expected Signature') return /(Invalid signature)/iu
  return new RegExp(exception, 'u')
}

const zeros32b = '00'.repeat(32)
const signatureIsZero = (s) => {
  if (typeof s === 'string') return s.startsWith(zeros32b) || s.endsWith(zeros32b)
  return s.subarray(0, 32).every((x) => x === 0) || s.subarray(32, 64).every((x) => x === 0)
}

export function fixVerifyResult(f) {
  delete f.strict // we don't support non-strict
  if (!f.exception && signatureIsZero(f.signature || f.s)) {
    // We error on zero signatures
    f.exception = 'Expected Signature'
  }
}
