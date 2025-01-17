'use strict'

function assertSize(size) {
  if (!(Number.isSafeInteger(size) && size > 0)) throw new TypeError('Invalid size')
}

module.exports = { assertSize }
