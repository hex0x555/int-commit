# Hash Commitment with Integer Sum Verification
This project takes integer inputs, comits their values, and verifies the correct sum of the values
## Libraries
- sha2, rand
## Functions
- Sha2: Hashing using SHA256
- Rand: Random blinding factor
- Commit: hashes the value with a random blinding factor. Creates a cryptographic commitment for a value using a random blinding factor. This ensures that the value is "hidden" but can be verified later when the blinding factor is revealed. This function is the core mechanism that ensures the value cannot be altered after commitment, preserving integrity and secrecy in the protocol.
- Prover: Generates a commitment for `a`, `b` and sends a challenge response. Acts as the prover in the protocol, generating commitments for two values and sharing a response that includes the blinding factor. The prover uses this function to create commitments for a and b that will later be validated by the verifier. The random blinding factor ensures that even if the same values are committed multiple times, the commitments will appear unique.
- Verifier: Checks if the sum `a + b = s` is correct and commitments are valid. Acts as the verifier in the protocol, checking if the commitments and the claimed sum are valid. commit_a: hashed value for a ; commit_b: hashed value for b ; a: The first value revealed by the prover ; b: The second value revealed by the prover ; r: The random blinding factor revealed by the prover ; s: The claimed sum of a + b.
- Main: Simulating a prover-verifier interaction. 
---
