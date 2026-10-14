# Threat model and trust boundaries

## Protected assets

- Safety-critical brake, steering, sensor, and alert messages.
- Vehicle and gateway identities.
- Session, OTA, and model-signing keys.
- Firmware, AI model, preprocessing, and policy artifacts.
- Security decisions and audit summaries.

## Considered attackers

- Passive eavesdroppers on Wi-Fi, Bluetooth, OTA, or V2X links.
- Active attackers modifying, injecting, replaying, delaying, or downgrading
  messages.
- Attackers supplying forged or rolled-back firmware/model artifacts.
- Resource-exhaustion attackers sending malformed or repeated packets.
- A temporarily unavailable central server.

## Trust boundaries

1. Sensor or ECU input enters the local feature and classification boundary.
2. The AI output enters the policy engine as one signal, not sole authority.
3. Plaintext becomes a signed and authenticated envelope before V2X transport.
4. A receiving ECU validates protocol context, signatures, freshness, replay
   state, and AEAD before accepting data.
5. Central monitoring receives alerts and summaries, not all raw messages.
6. OTA artifacts cross into the boot boundary only after signature, hash,
   target, expiry, and anti-rollback validation.

## Fail-safe rules

- Unknown location/interface values receive conservative risk.
- Resource pressure cannot reduce mandatory data/interface floors.
- Safety-critical restricted traffic requiring PQC fails closed if PQC is
  unavailable.
- `pqc_preferred` fallback is explicit and audited.
- Unknown suites, missing signatures, policy/profile mismatches, replayed
  sequences, expired envelopes, and modified ciphertext are rejected.
- Central-server outage does not stop local policy and peer verification.

## Explicit exclusions

The prototype does not claim protection against:

- A fully compromised endpoint, administrator, Python runtime, or signing
  authority.
- Physical extraction, side channels, RF jamming, or traffic analysis.
- Dishonest location input without hardware-backed location attestation.
- Training-data poisoning or malicious model authors.
- Hardware secure boot, TPM measurement, HSM key storage, or power-loss-safe
  production A/B switching.

These exclusions require deployment-specific hardware and protocol controls.
