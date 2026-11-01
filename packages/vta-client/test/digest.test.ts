// DigestMultibase: the same bytes dtg-credentials (the VTC's credential library) computes, so a bound member credential
// matches the grant the VTC stored.
import assert from "node:assert/strict";
import { test } from "node:test";
import { digestMultibase, digestsMatch } from "../src/index.js";

// The known answer from dtg-credentials 0.13.0's own test (lib.rs, `digest_multibase` of a `new_vmc`), computed there over
// this document's JCS form: sha-256 efcb1e10...4d07fe.
const VMC = {
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
  type: ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
  id: "urn:uuid:2a4e1d90-6e0c-4d3f-9a4a-6d0a8f7c1b52",
  issuer: "did:example:community",
  issuerScope: "public",
  validFrom: "2025-12-11T00:00:00Z",
  credentialSubject: { id: "did:example:member" },
};

test("digestMultibase matches dtg-credentials' known answer", () => {
  assert.equal(digestMultibase(VMC), "zQmeUhnd33Xp8egdUiQjPCVgANMXKSL7Nt5sCZbkcs2h2A1");
});

test("digestMultibase ignores the proof and member order", () => {
  const reordered = Object.fromEntries(Object.entries(VMC).reverse());
  assert.equal(digestMultibase({ ...reordered, proof: { type: "DataIntegrityProof", proofValue: "zabc" } }), digestMultibase(VMC));
  assert.notEqual(digestMultibase({ ...VMC, issuerScope: "directed" }), digestMultibase(VMC));
});

test("digestsMatch compares decoded sha2-256 multihashes and refuses other encodings", () => {
  const d = digestMultibase(VMC);
  assert.equal(digestsMatch(d, d), true);
  assert.equal(digestsMatch(d, digestMultibase({ ...VMC, id: "urn:uuid:other" })), false);
  assert.throws(() => digestsMatch("uEiA", d), /base58btc/);
  assert.throws(() => digestsMatch("z2", d), /sha2-256/);
});
