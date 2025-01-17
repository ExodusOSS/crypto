'use strict'

const crypto = require('crypto')
if (!crypto.webcrypto) throw new Error('Unexpected crypto-browserify or old Node.js crypto')

exports.randomUUID = crypto.randomUUID.bind(crypto)
