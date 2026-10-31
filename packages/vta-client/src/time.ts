// One timestamp form for every signed document the kit builds.
//
// `Date.prototype.toISOString()` always writes milliseconds, so an instant on an exact second comes out as
// `2026-10-31T12:00:00.000Z`. The VTA (vta-sdk, Rust/chrono) re-serialises `issuedAt` before it checks the proof and
// writes that instant as `2026-10-31T12:00:00Z`: the bytes it hashes are then not the bytes that were signed, and
// roughly one call in a thousand fails as "signature invalid". Wallets that talk to the VTA strip it the same way.
// `@openvtc/trust-tasks-proof` already writes `proof.created` this way; this helper does the same for the document.

/** RFC 3339, UTC, `Z`-terminated, with no fraction when it would be all zeros (chrono's form). */
export function rfc3339(d: Date = new Date()): string {
  return d.toISOString().replace(/\.000Z$/, "Z");
}
