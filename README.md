# `@exodus/crypto`

Reusable cryptography primitives, for browser/Node.js/Electron/React Native

For hashes not implemented by the platform, requires `@noble/hashes` dependency

## A note about React Native

* On React Native, methods that use randomness expect `globalThis.crypto.getRandomValues` to work.
  That can be polyfilled with `require('react-native-get-random-values')`.

* `Buffer` should be polyfilled (either globally or via a bundler).

## Regular API

### `randomBytes(size)`

```js
import { randomBytes } from '@exodus/crypto/randomBytes'
```

Returns a `Buffer` instance of length `size` filled from CSPRNG.

On non-Node.js environments, requires polyfilled `Buffer`.

### `randomUUID()`

```js
import { randomUUID } from '@exodus/crypto/randomUUID'
```

Returns a random UUID (version 4, variant 1), filled from CSPRNG.

This contains 122 bits of randomness.

Compatible with [Crypto.randomUUID()](https://developer.mozilla.org/docs/Web/API/Crypto/randomUUID).

### `await hash(type, arg[, form])`

```js
import { hash } from '@exodus/crypto/hash'
```

Hashes `arg` using the hash specified as `type`.

Returns the result as encoded as `form` (e.g. `'hex'`) or as a `Buffer` instance if `form` is not specified.

E.g.:
```console
> await hash('sha256', 'abc', 'hex')
'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
> await hash('sha256', Buffer.from('abc'), 'hex')
'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
> await hash('sha256', new Uint8Array([97, 98, 99]), 'hex')
'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
await hash('sha256', Buffer.from('abc'))
Buffer(32) [186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97, 163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173]
```

### `await hmac(type, secret, arg[, form])`

```js
import { hmac } from '@exodus/crypto/hmac'
```

HMAC implementation, usage similar to `hash()`.

Empty `secret` values are not supported.
