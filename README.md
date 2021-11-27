# TorC (Tor Controller for C/C++)
TorC is a [tor](https://torproject.org/) library for C/C++, written in C. With it you can use Tor's [control protocol](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt) to interface with a tor process.

## This is a work in progress
- More capabilities, support, and documentation coming soon.
- Will not support v2 features as of now, only v3

## Example (host an onionsite!)
A working example can be seen in `test/test.c`. This test opens a control port connection, creates a hidden service, and then serves http requests through the created hidden service. Tor must be running with its control port open to use this.

## Build Dependencies
- CMake
- OpenSSL
