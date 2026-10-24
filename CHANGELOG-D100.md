# D100 parser change log

## 2026-10-24

- Separate D100 door contact evidence from the new `door_inferred` binary sensor. Explicit door events update both; normal automatic locking only infers closed and invalidates a contradictory old open contact to unknown.
- Unlocking clears the inferred position to unknown. Knock, pry, stuck, anti-lock and child-lock events do not establish a closed door; secondary locks no longer overwrite the D100 main lock.
- Require authentication of the current packet and complete timestamped objects for D100 door/lock events. Accept events at most 120 seconds old or 30 seconds ahead; ignore older, out-of-order and duplicate objects. State evidence stays in memory and is not restored from old cached packets.
- Expose evidence source, event timestamp and inference status for compatible consumers. Radio silence does not imply that the door closed; inferred state is for comfort monitoring and is not security verification.
- Fix lock alarm handling so error IDs report an error without an uninitialized operator value or a successful lock operation.
- Validate with synthetic event sequences and the existing parser regression suite. Physical acceptance and deployment remain separate checks.

## 2026-10-20

- Add Aqara Door Lock D100: MiBeacon PID 3051 / 0x0BEB, ZNMS20LM (lumi.lock.bacn01).
- Reuse standard MiBeacon door, lock and fingerprint parsing.
- Report D100 battery percentage without deriving an unsupported CR2032 voltage.
- Add seven synthetic regression cases covering identity-only packets, encrypted open/close and lock events, battery percentage and wrong-key rejection.
- Verify the seven new cases and the 160 upstream parser tests. Synthetic coverage is not a claim of physical-device acceptance.

References: [lock adaptation discussion](https://bbs.hassbian.com/thread-25590-1-1.html), [D100 discussion](https://bbs.hassbian.com/thread-25570-1-1.html). No private device records or credentials are included.
