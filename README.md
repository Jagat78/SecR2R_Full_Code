# SecR2R

SecR2R is a C research prototype for secure robot-to-robot communication using
recorded SRAM-PUF readouts. It includes fuzzy extraction, P-256 protocol
cryptography, two-robot registration and authentication experiments, and
entropy-analysis tools.

This is a desktop replay of recorded data, not a live SRAM capture or a
production-ready security implementation. In particular, the protocol
EC-ElGamal adapter is malleable and does not provide ciphertext integrity on
its own.

## Repository contents

- `src/` — registration, authentication, entropy analysis, fuzzy-extractor,
  cryptography, and export code.
- `include/` — public headers for the C modules.
- `data/` — the CRPS dataset and selected-cell map used by the experiments.
- `results/` — checked-in sample analysis outputs.
- `test/` — authentication, forgery, and computation-cost test programs and
  recorded results.

## Requirements

- A C compiler with C11 support (`cc` or GCC)
- OpenSSL development headers and libraries
- Git LFS to download the large CRPS dataset
- `libm` for entropy analysis

On Windows, use a POSIX-compatible environment such as WSL, with the compiler
and OpenSSL development package installed there.

## Get the data

The `data/crps.csv` file is stored with Git LFS. Install Git LFS before cloning,
then fetch the dataset:

```sh
git lfs install
git clone https://github.com/Jagat78/SecR2R_Full_Code.git
cd SecR2R_Full_Code
git lfs pull
```

If the CSV contains only a short Git LFS pointer instead of dataset rows, run
`git lfs pull` after configuring Git LFS.

## Build

There is no build-system file yet. From the repository root, build the tools
with a C compiler and OpenSSL:

```sh
mkdir -p bin

cc -O2 -std=c11 -Wall -Wextra -Iinclude \
  src/registration.c src/bch.c src/fuzzy_extractor.c \
  src/secr2r_ecc_elgamal.c src/secr2r_hash.c \
  src/secr2r_protocol_crypto.c src/secure_random.c \
  -lcrypto -o bin/registration

cc -O2 -std=c11 -Wall -Wextra -Iinclude \
  src/authentication.c src/bch.c src/fuzzy_extractor.c \
  src/secr2r_ecc_elgamal.c src/secr2r_hash.c \
  src/secr2r_protocol_crypto.c src/secure_random.c \
  -lcrypto -o bin/authentication

cc -O2 -std=c11 -Wall -Wextra \
  src/entropy_analysis.c -lm -o bin/entropy_analysis
```

## Run

Run registration from the repository root. It selects two different robot IDs
and verifies alternate recorded readouts against the fuzzy-extractor helper
data. The optional third argument selects the output directory:

```sh
./bin/registration data/crps.csv data/selected_cells.csv registration_out
```

Registration generates robot and server CSVs, a server registry, and summary
files in `registration_out/`. It also writes
`registration_out/private_public_parameters.csv`, which contains private
secrets and PUF-derived data. Keep this file private and do not publish it.

To run the authentication simulation with those generated inputs:

```sh
./bin/authentication \
  data/crps.csv data/selected_cells.csv \
  registration_out/robot_A.csv \
  registration_out/robot_B.csv \
  registration_out/server.csv
```

Authentication writes protocol messages and other generated files beneath
`auth_outputs/`.

Run entropy analysis (the optional third argument is the output CSV path):

```sh
./bin/entropy_analysis \
  data/crps.csv data/selected_cells.csv results/entropy_summary.csv
```

Entropy analysis also writes weekly, per-cell, and per-device enrollment
summary CSVs alongside the requested output. Its empirical marginal entropy
estimates are not formal joint conditional min-entropy bounds; see the
interpretation column in `results/entropy_summary.csv`.

## Sensitive outputs

Generated registration and authentication files may contain private keys,
PUF responses, helper data, or protocol material. Review them before sharing
or committing. The checked-in `results/` and `test/` files are experiment
artifacts, not a substitute for independently reproducing the experiments.
