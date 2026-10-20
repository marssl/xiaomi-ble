# D100 parser change log

## 2026-10-20

- Add Aqara Door Lock D100: MiBeacon PID 3051 / 0x0BEB, ZNMS20LM (lumi.lock.bacn01).
- Reuse standard MiBeacon door, lock and fingerprint parsing.
- Report D100 battery percentage without deriving an unsupported CR2032 voltage.
- Add seven synthetic regression cases covering identity-only packets, encrypted open/close and lock events, battery percentage and wrong-key rejection.
- Verify the seven new cases and the 160 upstream parser tests. Synthetic coverage is not a claim of physical-device acceptance.

References: [lock adaptation discussion](https://bbs.hassbian.com/thread-25590-1-1.html), [D100 discussion](https://bbs.hassbian.com/thread-25570-1-1.html). No private device records or credentials are included.
