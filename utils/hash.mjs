import { fromUint8Array } from './output.js'

// Hash utils for @noble/* wrappers

function checkHashInput(arg, form) {
  // This also covers Buffer as they are Uint8Array instances
  if (!(typeof arg === 'string' || arg instanceof Uint8Array)) {
    if (Array.isArray(arg)) {
      // Allow hashing an non-empty array of Uint8Array instances or Buffer instances
      if (!(arg.length > 0)) throw new Error('An array in hash argument must not be empty')
      for (const x of arg) {
        if (x instanceof Uint8Array) continue
        throw new Error('Unsupported entry in hash argument')
      }
    } else {
      throw new Error('Unsupported hash argument')
    }
  }

  // Early check for output type, this is rechecked later in fromUint8Array
  if (!['hex', 'buffer', 'uint8'].includes(form)) throw new Error('Unsupported output format')
}

export function hashWrap(method, options) {
  return function(input, form = 'buffer') {
    checkHashInput(input, form)
    if (Array.isArray(input)) {
      const state = method.create(options)
      for (const entry of input) state.update(entry)
      return fromUint8Array(state.digest(), form)
    }
    return fromUint8Array(method(input, options), form)
  }
}
