import { ECPairFactory } from 'ecpair'
import * as secp256k1 from '../secp256k1.mjs'

import { test } from '@exodus/test/jest'

test('ecpair internal tests', () => {
  ECPairFactory(secp256k1.tiny_secp256k1_compat)
})
