# wolfCrypt Example

Tested Boards:

* PCA10040: nRF52832 - Cortex M4 64MHz
* PCA10056: nRF52840 - Cortex M4 64MHz

## nRF5 SDK Configuration

```sh
# Set the toolchain path in makefile.posix
# vim ./components/toolchain/gcc/makefile.posix
# OR
# setup this environment variables
export GNU_INSTALL_ROOT=/opt/gcc-arm-none-eabi/bin/
export GNU_VERSION=9.2.1
export GNU_PREFIX=arm-none-eabi

make sdk_config
```

## nRF5 wolfCrypt Example

```sh
cd ./examples/crypto/wolfcrypt/pca10040/armgcc/
make flash
```

### wolfCrypt Example output from UART

```
				MENU

	c. wolfCrypt Algo Example
	t. WolfCrypt Test
	b. WolfCrypt Benchmark
Please select one of the above options:

c
Running wolfCrypt Algo Tests...
RNG Generate Block Sz 64: Ret 0
SHA256 Hash Plain: Ret 0
ECDSA (SECP256R1): Ret 0
ECDHE (SECP256R1): Ret 0
X963 KDF (SHA256): Ret 0
AES-GCM Encrypt: Ret 0
wolfCrypt Algo Example: Return code  (0)

t
Running wolfCrypt Tests...
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
error    test passed!
MEMORY   test passed!
base64   test passed
RANDOM   test passed!
SHA-256  test passed!
Hash     test passed!
X963-KDF    test passed!
GMAC     test passed!
AES      test passed!
AES-GCM  test passed!
ECC      test passed!
ECC buffer test passed!
logging  test passed!
mutex    test passed!
Test complete
Crypt Test: Return code 0

b
Running wolfCrypt Benchmarks...
------------------------------------------------------------------------------
 wolfSSL version 4.4.1
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each
RNG                325 KB took 1.046 seconds,  310.707 KB/s
AES-128-GCM-enc    300 KB took 1.073 seconds,  279.590 KB/s
SHA-256           1000 KB took 1.022 seconds,  978.474 KB/s
ECC      256 key gen        41 ops took 1.009 sec, avg 24.610 ms, 40.634 ops/sec
ECDHE    256 agree          20 ops took 1.033 sec, avg 51.650 ms, 19.361 ops/sec
ECDSA    256 sign           28 ops took 1.054 sec, avg 37.643 ms, 26.565 ops/sec
ECDSA    256 verify         14 ops took 1.118 sec, avg 79.857 ms, 12.522 ops/sec
Benchmark complete
Benchmark Test: Return code 0
```

Benchmarks for SECP224R1 (define `NO_ECC256`):

```
ECC      224 key gen         3 ops took 1.446 sec, avg 482.000 ms, 2.075 ops/sec
ECDHE    224 agree           4 ops took 1.914 sec, avg 478.500 ms, 2.090 ops/sec
ECDSA    224 sign            4 ops took 1.955 sec, avg 488.750 ms, 2.046 ops/sec
ECDSA    224 verify          4 ops took 1.275 sec, avg 318.750 ms, 3.137 ops/sec
```

The reason SECP224R1 is slower is because 224-bit curves are not being accelerated with the SP Math Cortex-M assembly (SP math only supports 256 and 384 bit prime curves).

## Debugging

```sh
JLinkGDBServer -if SWD -device nRF52832_xxAA

arm-none-eabi-gdb _build/nrf52832_xxaa.out
target remote :2331
```
