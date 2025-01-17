import { tiny_secp256k1_compat as secp256k1 } from '../secp256k1.mjs'

// import test_ecdsa from './tiny-secp256k1/ecdsa.mjs'
import test_points from './tiny-secp256k1/points.mjs'
import test_privates from './tiny-secp256k1/privates.mjs'
import test_schnorr from './tiny-secp256k1/schnorr.mjs'

// tiny-secp256k1 tests also match bitcoinerlab (see last two notes though)
/* We have some differences:
1. verify/verifySchnorr throws not only on sigs > n, but also on sigs = 0
2. we don't support non-strict verification
3. default entropy is random in signSchnorr
4. error messages differ
5. recover is not supported
6. xOnlyPointAddTweakCheck not supported (also not present in bitcoinerlab)
*/

test_schnorr(secp256k1, 'tiny_secp256k1_compat')
// test_ecdsa(secp256k1, 'tiny_secp256k1_compat') // Moved to a separate file for perf
test_points(secp256k1, 'tiny_secp256k1_compat')
test_privates(secp256k1, 'tiny_secp256k1_compat')
