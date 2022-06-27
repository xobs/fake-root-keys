# Fake Rootkey Server

This is a fake server to operate as a drop-in replacement for `root-keys`. It enables `pddb` to run on
a device without a graphics server, a modal server, or a GAM.

## Background

This server is designed to be used when testing the PDDB and running experiments with the API.
It makes it easy to run a slimmer system without needing to have user interaction. It fakes
most of the requests that PDDB makes, including:

* Modal Dialog Server
* GAM
* Graphics Layer
* Timeserver

This should not be used in a production environment. It does not support updates.

## UX

This keys server should behave exactly like a normal `root-keys` server, with the addition of
opcode #34: `InitBootPassword`. To unlock and init the boot password, send this message along
with a string in a `MemoryMessage` with `valid` set to the length of the password. This will
simulate the same password unlock sequence as the user typing in their password.

## Compiling

To compile, this repository needs to have the `aes` and `utralib` crates from Xous Core.
Modify `Cargo.toml` to have these point at the appropriate paths.