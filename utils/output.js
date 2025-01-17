'use strict'

// Only to be ever used on underlying implementations outputs, as it uses a no-copy conversion where possible

function fromUint8Array(arr, form = 'buffer') {
  if (!['hex', 'buffer', 'uint8'].includes(form)) {
    throw new Error('Unsupported output format')
  }
  if (!(arr instanceof Uint8Array && arr.constructor === Uint8Array)) {
    throw new Error('Unreachable')
  }
  if (form === 'uint8') return arr // no-copy
  const buf = Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength) // no-copy
  if (form === 'buffer') return buf
  return buf.toString(form)
}

// From Uint8Array or a Buffer, defaults to uint8 for new curve APIs
function fromUint8Super(arr, form = 'uint8') {
  if (!['hex', 'buffer', 'uint8'].includes(form)) {
    throw new Error('Unsupported output format')
  }
  if (!(arr instanceof Uint8Array)) throw new Error('Unreachable')
  switch (form) {
    case 'uint8':
      if (arr.constructor === Uint8Array) return arr // fast path
      return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength)
    case 'buffer':
      if (arr.constructor === Buffer && Buffer.isBuffer(arr)) return arr
      return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength)
    case 'hex':
      if (arr.constructor === Buffer && Buffer.isBuffer(arr)) return arr.toString('hex')
      return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength).toString('hex')
  }
  throw new Error('Unreachable')
}

function fromArrayBuffer(buf, form) {
  if (!(buf instanceof ArrayBuffer && buf.constructor === ArrayBuffer)) {
    throw new Error('Unreachable')
  }
  return fromUint8Array(new Uint8Array(buf), form)
}

function fromHash(hash, form = 'buffer') {
  if (form === 'hex') return hash.digest(form)
  const buf = hash.digest()
  if (form === 'buffer') return buf
  if (form === 'uint8') return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  throw new Error('Unsupported output format')
}

module.exports = { fromUint8Array, fromUint8Super, fromArrayBuffer, fromHash }
