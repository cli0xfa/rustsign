# Test data

`test_key.pem` and `test_combined.pem` contain the private key for the
self-signed `Test Code Signing` certificate. This is a deliberately public,
untrusted test fixture used by automated tests. Never use it to sign real
software or as a trusted production certificate.

`extracted-chain/` contains public certificate-chain samples only; it contains
no private keys. PFX/P12 files and other private certificate containers should
stay outside the repository. The Git ignore rules exclude these formats.
