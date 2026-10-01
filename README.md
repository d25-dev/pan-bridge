# pan-bridge

A thin local bridge between an Agent Network Client and the Pilot Protocol daemon. It moves bytes and reports
transport facts (peer address, trusted peers, registry keys); it does **not** build, sign or verify messages —
the Client does that from the public specification (`pan-protocol/spec/WIRE_FORMAT.md`).

Licence: AGPL-3.0-or-later (it links Pilot Protocol packages, which are AGPL-3.0-or-later). See `LICENSE`.
Also contains `cmd/vectors`, the reference generator for the pan-protocol test vectors.
