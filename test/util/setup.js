'use strict'

/* eslint-disable no-extend-native */
// This is needed to compare bound functions for equality
function mockSingularFunctionBind() {
  const { bind } = Function.prototype
  Function.prototype.bind = function bind2(...args) {
    Function.prototype.bind = bind
    const result = bind.apply(this, args)
    result.source = this.source || this
    result.args = [args[0], ...(this.args || []).slice(1), ...args.slice(1)]
    Function.prototype.bind = bind2
    return result
  }
}
/* eslint-enable no-extend-native */

module.exports = { mockSingularFunctionBind }
