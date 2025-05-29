# secure-remote-logger

# Overview
A secure logging system that ensures remote logs are tamper-evident using cryptographic hashing and proof-of-work. Implemented in java, this project features a client-server architecture for logging events, with PoW to deter tampering and ensure integrity.

# Features
- Tamper-Evident Logging: Uses cryptographic hashing to chain logs, making tampering detectable.
- Proof of Work: Requires computational effort to append logs, enhancing security.
- Client-Server Architecture: Supports remote logging over TCP/IP (or similar protocol).
- Robust Error Handling: Manages network failures, invalid inputs, and edge cases.
- Scalable Design: Handles logs of varying sizes and frequencies.

