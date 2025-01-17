import test from '@exodus/test/tape'
import { fromHex, makeErrorRegex } from './util.mjs'
import { loadFixture } from './load-fixture.js'

const fprivates = loadFixture('privates')

export default function(secp256k1, type) {
  test(`isPrivate (${type})`, (t) => {
    for (const f of fprivates.valid.isPrivate) {
      const d = fromHex(f.d)

      t.equal(secp256k1.isPrivate(d), f.expected, `${f.d} is ${f.expected ? 'OK' : 'rejected'}`)
    }

    t.end()
  })

  test(`privateAdd (${type})`, (t) => {
    for (const f of fprivates.valid.privateAdd) {
      const d = fromHex(f.d)
      const tweak = fromHex(f.tweak)
      const expected = f.expected ? fromHex(f.expected) : null
      let description = `${f.d} + ${f.tweak} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(secp256k1.privateAdd(d, tweak), expected, description)
    }

    for (const f of fprivates.invalid.privateAdd) {
      const d = fromHex(f.d)
      const tweak = fromHex(f.tweak)

      t.throws(
        () => {
          secp256k1.privateAdd(d, tweak)
        },
        makeErrorRegex(f.exception),
        `${f.description} throws ${f.exception}`
      )
    }

    t.end()
  })

  test(`privateSub (${type})`, (t) => {
    for (const f of fprivates.valid.privateSub) {
      const d = fromHex(f.d)
      const tweak = fromHex(f.tweak)
      const expected = f.expected ? fromHex(f.expected) : null
      let description = `${f.d} - ${f.tweak} = ${f.expected ? f.expected : null}`
      if (f.description) description += ` (${f.description})`

      t.same(secp256k1.privateSub(d, tweak), expected, description)
    }

    for (const f of fprivates.invalid.privateSub) {
      const d = fromHex(f.d)
      const tweak = fromHex(f.tweak)

      t.throws(
        () => {
          secp256k1.privateSub(d, tweak)
        },
        makeErrorRegex(f.exception),
        `${f.description} throws ${f.exception}`
      )
    }

    t.end()
  })
}
