# Cryptography on OpenVMS x86-64

## What WireGuard needs

- Curve25519 (X25519) for the Diffie-Hellman key exchange
- ChaCha20-Poly1305 (AEAD) for transport data encryption
- BLAKE2s for hashing/MAC within the Noise handshake and cookie mechanism
- HKDF (built from the above) for key derivation

## Availability on OpenVMS x86-64

- **OpenSSL 3.x is officially ported and maintained** for OpenVMS x86-64 as
  VSI's "SSL3" product, tracking upstream OpenSSL 3.0.x/3.1.x releases (a
  3.0.10-based update has shipped for x86). OpenSSL 3.x's EVP interface
  covers X25519, ChaCha20-Poly1305, and BLAKE2s directly — this should be
  sufficient for all of WireGuard's primitive needs without porting
  anything else.
- Older OpenSSL 1.1.1-based packaging (`SSL111`) also exists as a VSI
  product for other OpenVMS platforms; for x86-64, prefer SSL3 for
  BLAKE2s/X25519 EVP support.
- **libsodium**: no OpenVMS x86-64 port found. Not needed given OpenSSL 3's
  coverage, but worth rechecking if OpenSSL's BLAKE2s support turns out to
  have gaps on this platform.

## To verify on the target system

- [ ] Confirm SSL3 (or whichever OpenSSL package) is installed and its exact
      version
- [ ] Confirm `EVP_PKEY_X25519`, `EVP_chacha20_poly1305`, and BLAKE2s
      (`EVP_blake2s256`) are all present and functional in the installed
      build (some distro/vendor OpenSSL builds trim algorithms)
- [ ] Decide whether to link OpenSSL statically or dynamically for the
      vmsguard binary
