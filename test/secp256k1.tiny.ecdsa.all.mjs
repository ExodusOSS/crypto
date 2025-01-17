import { tiny_secp256k1_compat as secp256k1 } from '../secp256k1.mjs'

import test_ecdsa from './tiny-secp256k1/ecdsa.mjs'

// See comment in tiny.all.mjs

test_ecdsa(secp256k1, 'tiny_secp256k1_compat')
