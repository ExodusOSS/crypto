'use strict'

const crypto = globalThis.crypto

exports.randomUUID = crypto.randomUUID.bind(crypto)
