// Every signed document the kit builds stamps issuedAt (and the proof's created) without a ".000Z" fraction: the VTA
// re-serialises those instants before hashing, so the ".000Z" form fails as "signature invalid" on an exact second.
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { VtaClient, buildDecision, newIdentity, rfc3339 } from "../src/index.js";

const EXACT = Date.parse("2026-10-31T12:00:00.000Z");

test("rfc3339 drops an all-zero fraction and keeps a real one", () => {
  assert.equal(rfc3339(new Date(EXACT)), "2026-10-31T12:00:00Z");
  assert.equal(rfc3339(new Date(EXACT + 123)), "2026-10-31T12:00:00.123Z");
});

test("on an exact second, VtaClient.call and buildDecision never sign a .000Z issuedAt or proof.created", async (t) => {
  mock.timers.enable({ apis: ["Date"], now: EXACT });
  t.after(() => mock.timers.reset());
  let sent: any;
  const fetchImpl = (async (_u: any, init: any) => {
    sent = JSON.parse(init.body);
    return new Response(JSON.stringify({ type: sent.type + "#response", threadId: sent.id, payload: {} }));
  }) as typeof fetch;
  const c = new VtaClient("http://vta.test", "did:example:vta", newIdentity(), fetchImpl);
  await c.whoami();
  assert.equal(sent.issuedAt, "2026-10-31T12:00:00Z");
  assert.equal(sent.proof.created, "2026-10-31T12:00:00Z");
  const decision = buildDecision(
    { document: {}, payload: { challenge: "c", payloadDigest: "z1" }, matchCode: "abc123", effects: [], expiresAt: "" },
    newIdentity(), "did:example:vta", { approve: false },
  );
  assert.equal(decision.issuedAt, "2026-10-31T12:00:00Z");
  assert.equal(decision.proof.created, "2026-10-31T12:00:00Z");
  assert.doesNotMatch(JSON.stringify([sent, decision]), /\.000Z/);
});
