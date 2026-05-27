# Fuzz corpus — DER parser seeds

Place binary seed files in this directory before running `fuzz_der`.

## Recommended seeds

### DER ECDSA signatures (`selector = 0x00`)
Files must start with `0x00`, followed by a raw DER ECDSA signature.
A minimal valid P-256 DER signature (70–72 bytes) looks like:
  `30 44 02 20 <r[32]> 02 20 <s[32]>`

Extract a real signature from any Cryptnox transaction and prepend `0x00`.

### Manufacturer certificate blobs (`selector = 0x01`)
Files must start with `0x01`, followed by a raw DER X.509 certificate.
Obtain a real Cryptnox manufacturer certificate via
`CW_SecureChannel::getManufacturerCertificate()` and prepend `0x01`.

## Example (Linux/macOS)
```
# Prepend selector byte 0x01 to an existing DER cert
printf '\x01' | cat - mfr_cert.der > corpus/cert_01.bin

# Prepend selector byte 0x00 to an existing DER signature
printf '\x00' | cat - sig.der > corpus/sig_00.bin
```

## Running the fuzzer
```
cd cryptnox-sdk-cpp/fuzz
mkdir build && cd build
cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
make
./fuzz_der ../corpus/ -max_len=512 -jobs=4
```
