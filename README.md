# Bore: Boring file encryption

**This is a work in progress.**

It hasn't been tested and reviewed heavily enough yet, which makes it
too interesting to use for now.  Check back in a little while to see if
it's gotten boring in the meantime.

## What is bore?

Bore is a command-line tool to solve the task of securely
encrypting a file using either a secret key file,
or a secret password that's [hard to guess](https://xkcd.com/936).

Bore aims to ensure (not in the legal sense) the following facts:

- If you keep the key file secret, or you use a strong password which you keep secret
- Then you can encrypt any number of files of any size
- You can send and receive the resulting ciphertexts (files ending in
  `.bore`) to and from anywhere
- The contents of the files will remain secret
    - Caveat: The lengths of the files will not be secret
- You can decrypt the ciphertexts with the same key/password you used to
  encrypt them
- You will either get back the exact same files that you started with, or an error
    - Caveat: Files are identified by name, so if you encrypt two files
      with the same name, you won't be able to tell later which one is which.

## What isn't bore?

- Bore does not solve the problem of sending files to someone other than
  yourself.
- Bore is not suitable for use as a library.
- Bore might contain mistakes and is thus not suitable for
  life-and-death situations.

## Usage

### Key generation

    bore gen-key <keyfile>

### Encrypting

With a key:

    bore seal -f <keyfile> <data>

With a strong password:

    bore seal -p <password-file> <data>

### Decrypting

    bore open -f <keyfile> <data>.bore

or

    bore open -p <password-file> <data>.bore

## How does bore work?

It uses [`sodiumoxide::crypto::secretstream`][secretstream] to
authenticated-encrypt files in chunks.
It also authenticated-encrypts the original filename.
`sodiumoxide` is a Rust wrapper around `libsodium`, which is a portable
implementation of the NaCl API.

## TODO

- GUI
- Better handling of OS strings vs Rust strings
- Unit and integration tests
- Write clear guide on how to generate a strong password
- rename `seal` and `open`

[secretstream]: https://docs.rs/sodiumoxide/0.2.4/sodiumoxide/crypto/secretstream/index.html

# Copyright

Bore Copyright 2019 Lily Chung

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this software except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
