'use strict'

// Expects a global Buffer instance even in processes without Node.js integration

// Prefers Node.js implementation

if (typeof process === 'object' && !process.browser) {
  module.exports = require('./randomBytes.node.js')
} else {
  module.exports = require('./randomBytes.browser.js')
}
