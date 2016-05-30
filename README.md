# mruby-sysrandom

Secure random number generation for mruby using system RNG facilities e.g. /dev/urandom, getrandom(2)

## Description

In cryptography circles, [the prevailing advice is to use OS RNG functionality][/dev/urandom],
namely `/dev/urandom` or equivalent calls which use an OS-level CSPRNG to
produce random numbers.

This gem provides an easy-to-install repackaging of the `randombytes`
functionality from [libsodium] for the purpose of generating secure random
numbers trustworthy for use in cryptographic contexts, such as generating
cryptographic keys, initialization vectors, or nonces.

The following random number generators are utilized:

| Platform | RNG                                                    |
|----------|--------------------------------------------------------|
| Linux    | [getrandom(2)] if available, otherwise [/dev/urandom]  |
| Windows  | [RtlGenRandom] CryptGenRandom without CryptoAPI deps   |
| OpenBSD  | [arc4random(3)] with ChaCha20 CSPRNG (not RC4)         |
| JRuby    | [NativePRNGNonBlocking] on Java 8, otherwise SHA1PRNG  |
| Others   | [/dev/urandom]                                         |

[emboss]:        https://emboss.github.io/blog/2013/08/21/openssl-prng-is-not-really-fork-safe/
[bug]:           https://bugs.ruby-lang.org/issues/9569
[libsodium]:     https://github.com/jedisct1/libsodium
[getrandom(2)]:  http://man7.org/linux/man-pages/man2/getrandom.2.html
[/dev/urandom]:  http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/
[RtlGenRandom]:  https://msdn.microsoft.com/en-us/library/windows/desktop/aa387694(v=vs.85).aspx
[arc4random(3)]: http://man.openbsd.org/arc4random.3
[NativePRNGNonBlocking]: https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/

## Usage

```ruby
Sysrandom.random_bytes

Sysrandom.random_bytes(64)

Sysrandom.random_bytes(" " * 10)

Sysrandom.random # returns a number

Sysrandom.uniform(upper_bound) # returns a number up to upper_bound

Sysrandom.base64

Sysrandom.base64(64)

Sysrandom.hex

Sysrandom.hex(64)
```
