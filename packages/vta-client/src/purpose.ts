// Which proof purpose a document is signed for (SPEC 4.7.3 "Which purpose a producer signs with"): `authentication` for
// an ordinary request, `assertionMethod` only where the task spec defines an attestation. The slug list and the rule
// mirror the pinned VTA (vta-sdk `trust_task_proof::purpose::purpose_for_document_type`, ATTESTATION_SLUGS): only a
// request (not a #response) of a registry Type URI under one of these slugs is an attestation.

export type ProofPurpose = "authentication" | "assertionMethod" | "capabilityInvocation" | "capabilityDelegation";

/** Purposes that authorise a signature. `keyAgreement` never does, and an unknown value is not a purpose. */
export const SIGNING_PURPOSES: readonly ProofPurpose[] = ["authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"];

export const ATTESTATION_SLUGS = ["auth/step-up/approve-response", "task-consent/decision", "confirm/response", "auth/oob/grant"] as const;

const REGISTRY = /^https:\/\/trusttasks\.org\/spec\/(.+)\/(\d+)\.(\d+)(#request)?$/;

/** The purpose to sign a document of `type` for. Verifiable credentials are not Trust Tasks: sign those for assertionMethod. */
export function purposeFor(type: string): ProofPurpose {
  const m = REGISTRY.exec(type);
  return m && (ATTESTATION_SLUGS as readonly string[]).includes(m[1]) ? "assertionMethod" : "authentication";
}

/** True when `p` is a purpose that can authorise a signature (SPEC 4.7.3 item 1: refuse keyAgreement or an unknown value). */
export function isSigningPurpose(p: unknown): p is ProofPurpose {
  return typeof p === "string" && (SIGNING_PURPOSES as readonly string[]).includes(p);
}
