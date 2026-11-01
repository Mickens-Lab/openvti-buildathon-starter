// The community's membership credential (the grant) as this page received it, and the words for sending one's own back.
//
// The grant reaches the member only in the `credential-exchange/issue` frame the VTC pushes at approval: over TSP, so only in
// MODE=tunnel, and only if the "Credential frames" panel was listening when it came (the member cannot read its own grant over
// REST: `vtc/members/credentials/0.1` is admin only). listener.ts puts it here; the membership card's "Send my membership
// credential back" binds to it when it is here (digestMultibase + validUntil cap, vtc-client `memberVmc`) and sends an
// unbound one otherwise. Kept in memory only: a reload forgets it, and the next issue frame brings it back.
import { createStore } from "./store.ts";
import type { RunMode } from "./delivery.ts";

export const membershipGrant = createStore<Record<string, unknown> | undefined>(undefined);

/** Why the page has no grant to bind to, in the reader's terms. */
export function noGrantReason(mode: RunMode): string {
  if (mode === "local") return "The local stack has no messaging, so the community's own membership credential (the grant) never reaches this page.";
  if (mode === "tunnel") return "This page has not received the community's membership credential (the grant): it arrives as a credential-exchange/issue frame, so open \"Credential frames\" and press Listen before the administrator approves (a reload forgets it).";
  return "Whether a hosted community pushes its membership credential (the grant) to this page is unverified, and none has arrived.";
}

/** The confirm text for "Send my membership credential back". */
export function sendBackConfirm(bound: boolean, mode: RunMode): string {
  const head = "This signs a membership credential with your app key, naming this community as its subject, and sends it to the community.";
  if (bound) return `${head} It carries the digest of the membership credential the community issued to you (the grant this page received) and expires no later than it, so the community checks the digest and stores it bound, completing your membership pair, or refuses it if the digest does not match. Continue?`;
  return `${head} ${noGrantReason(mode)} So it carries no digest of that grant: the community stores it unbound and records your membership pair as incomplete. Continue?`;
}

/** The sentence the delivery note uses once the community holds a credential from this member. */
export function heldDetail(sentBound: boolean | undefined): string {
  const base = "The community reports it holds your own membership credential sent back to it (that is what credentialsDelivered means; it is not a frame receipt).";
  if (sentBound === true) return `${base} The one this page sent carries the digest of the community's grant, and the community stored it (it refuses a digest that does not match), so your membership pair is complete.`;
  if (sentBound === false) return `${base} The one this page sent carries no digest of the community's grant, so the community stores it unbound and records the membership pair as incomplete.`;
  return `${base} Whether it is bound to the community's grant depends on what was sent: one without the grant's digest is stored unbound (the pair incomplete).`;
}
