import assert from "node:assert/strict";
import { test } from "node:test";
import { newIdentity } from "@buildathon/vta-client";
import { createInbox } from "../src/inbox.js";
import { makeNote } from "../src/send.js";

const ME = "did:web:inbox.test";

test("accepts a signed note once; a replay does not execute again", async () => {
  const inbox = createInbox(ME);
  const doc = makeNote(newIdentity(), ME, "t", "b");
  assert.equal((await inbox.receive(doc as any)).kind, "accepted");
  assert.equal((await inbox.receive(doc as any)).kind, "duplicate");
  assert.equal(inbox.notes.length, 1);
});

test("rejects tampered, unsigned and misaddressed documents", async () => {
  const inbox = createInbox(ME);
  const me = newIdentity();
  const tampered: any = makeNote(me, ME, "t", "b");
  tampered.payload.body = "x";
  const unsigned: any = makeNote(me, ME, "t", "b");
  delete unsigned.proof;
  for (const doc of [tampered, unsigned, makeNote(me, "did:web:other", "t", "b")]) {
    assert.equal((await inbox.receive(doc)).kind, "rejected");
  }
  assert.equal(inbox.notes.length, 0);
});

test("makeNote on an exact second signs no .000Z issuedAt or proof.created", async (t) => {
  const { mock } = await import("node:test");
  mock.timers.enable({ apis: ["Date"], now: Date.parse("2026-10-31T12:00:00.000Z") });
  t.after(() => mock.timers.reset());
  const doc: any = makeNote(newIdentity(), ME, "t", "b");
  assert.equal(doc.issuedAt, "2026-10-31T12:00:00Z");
  assert.equal(doc.proof.created, "2026-10-31T12:00:00Z");
});
