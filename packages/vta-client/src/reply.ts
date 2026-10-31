// What a reply to a Trust Task document means, decided the way the framework says (SPEC 4.4.1): by the reply's own
// `type` and nothing else. Shared by the VTA and VTC clients.
//
//   success       the request's Type URI with the fragment `#response`
//   failure       https://trusttasks.org/spec/trust-task-error/<MAJOR.MINOR>
//   continuation  https://trusttasks.org/spec/trust-task-next-step/<MAJOR.MINOR>  (the exchange is NOT closed)
//
// The HTTPS binding (0.3, section 4) adds two answers with no body at all: `202` (a duplicate of a document whose first
// execution is still running) and `204` (done, and the task defines no response, or a duplicate whose response was not
// kept). Neither is a failure, and a producer must not treat either as one.

export const ERROR_TYPE_PREFIX = "https://trusttasks.org/spec/trust-task-error/";
export const NEXT_STEP_TYPE_PREFIX = "https://trusttasks.org/spec/trust-task-next-step/";

/** A request Type URI without its explicit `#request` fragment (the two forms mean the same, SPEC 4.4.1 rule 1). */
export function bareType(type: string): string {
  return type.endsWith("#request") ? type.slice(0, -"#request".length) : type;
}

/** True when `docType` is a request of `taskType`: the bare URI or its `#request` form. Never a `#response`. */
export function isRequestOf(docType: unknown, taskType: string): boolean {
  if (typeof docType !== "string") return false;
  const bare = bareType(taskType);
  return docType === bare || docType === `${bare}#request`;
}

/** The success-response type of a request type. */
export function responseTypeOf(type: string): string {
  return `${bareType(type)}#response`;
}

export type ReplyKind =
  /** `#response` of the request's type: the payload is the result. */
  | "response"
  /** `trust-task-error`: refused or failed; `code` says why. */
  | "error"
  /** `trust-task-next-step`: accepted, still blocked; not a result and not a failure. */
  | "next-step"
  /** HTTP 202 with no body: a duplicate of a document whose first execution has not finished. */
  | "in-flight"
  /** HTTP 204 with no body: done, with no response document. */
  | "no-response"
  /** Anything else: not JSON, not a Trust Task document, or another task's response. */
  | "unexpected";

export interface Reply {
  kind: ReplyKind;
  /** HTTP status (informative only; the `type` decides). */
  status: number;
  /** The reply document, when there was one. */
  document?: any;
  /** The reply's payload (`response`, `error`, `next-step`). */
  payload?: any;
  /** The framework error code for `error` (e.g. `permissionDenied`, `taskFailed`, `acl/grant:someCode`). */
  code?: string;
  /** Why an `unexpected` reply was not accepted. */
  reason?: string;
  /** The raw body text when it was not a JSON document. */
  text?: string;
  /**
   * The reply names a different exchange: its `threadId` is neither the request's `threadId` nor (when the request had
   * none) its `id`. SPEC 4.9 makes this a SHOULD for the responder and forbids rejecting on `threadId` alone, so it is
   * reported, not refused.
   */
  threadMismatch?: boolean;
}

/** The framework error code of an error document or error body, e.g. `permissionDenied`, or undefined. */
export function refusalCode(body: unknown): string | undefined {
  const c = (body as any)?.payload?.code ?? (body as any)?.code;
  return typeof c === "string" ? c : undefined;
}

/** `details` of an error document, when it has them. */
export function refusalDetails(body: unknown): Record<string, unknown> | undefined {
  const d = (body as any)?.payload?.details;
  return d && typeof d === "object" ? d : undefined;
}

/** Classify one HTTP reply to `request` (the document that was sent). Never throws. */
export function classifyReply(request: { id?: string; type: string; threadId?: string }, status: number, text: string): Reply {
  if (text.trim() === "") {
    if (status === 202) return { kind: "in-flight", status };
    if (status === 204) return { kind: "no-response", status };
    return { kind: "unexpected", status, text, reason: `an empty body with HTTP ${status}` };
  }
  let doc: any;
  try {
    doc = JSON.parse(text);
  } catch {
    return { kind: "unexpected", status, text, reason: "the body is not JSON" };
  }
  return classifyDocument(request, doc, status);
}

/** Classify a reply document already parsed (e.g. one that arrived over TSP). `status` is 0 when there was no HTTP. */
export function classifyDocument(request: { id?: string; type: string; threadId?: string }, doc: any, status = 0): Reply {
  const type = typeof doc?.type === "string" ? doc.type : undefined;
  const expectedThread = request.threadId ?? request.id;
  const threadMismatch = typeof doc?.threadId === "string" && expectedThread !== undefined && doc.threadId !== expectedThread ? true : undefined;
  const base = { status, document: doc, ...(threadMismatch ? { threadMismatch } : {}) };
  if (type === responseTypeOf(request.type)) return { kind: "response", ...base, payload: doc.payload };
  if (type?.startsWith(ERROR_TYPE_PREFIX)) return { kind: "error", ...base, payload: doc.payload, code: refusalCode(doc) };
  if (type?.startsWith(NEXT_STEP_TYPE_PREFIX)) return { kind: "next-step", ...base, payload: doc.payload };
  return {
    kind: "unexpected",
    ...base,
    code: refusalCode(doc),
    reason: type ? `a reply of type ${type}, not ${responseTypeOf(request.type)}` : "the body is not a Trust Task document (no type)",
  };
}

/** A refusal, a failure, or a reply that is not a Trust Task answer to the request. `body` is the reply (or its text). */
export class TrustTaskError extends Error {
  constructor(
    public status: number,
    public body: unknown,
    /** The classified reply, when the client had one. */
    public reply?: Reply,
  ) {
    super(`Trust Task failed (HTTP ${status}): ${typeof body === "string" ? body : JSON.stringify(body)}`);
  }

  /** The framework error code, e.g. `permissionDenied`, or undefined (not an error document). */
  get code(): string | undefined {
    return refusalCode(this.body);
  }

  /** The error document's `details`, when it has them. */
  get details(): Record<string, unknown> | undefined {
    return refusalDetails(this.body);
  }
}

/**
 * Accepted but not finished: a `trust-task-next-step` continuation (`reply.document` says what is needed next), or a
 * 202 for a duplicate whose first execution is still running. Not a failure: do not reissue a consequential task.
 */
export class TrustTaskPending extends Error {
  constructor(public reply: Reply) {
    super(
      reply.kind === "next-step"
        ? `Trust Task not finished: the consumer answered trust-task-next-step (${reply.document?.type}); it is blocked until the next step is done`
        : `Trust Task not finished: HTTP ${reply.status}, an earlier copy of this document is still executing`,
    );
  }
}

/** The result payload of a reply, or a throw: {@link TrustTaskError} for a failure, {@link TrustTaskPending} for a continuation. */
export function unwrapReply<R = any>(reply: Reply): R {
  switch (reply.kind) {
    case "response":
      return reply.payload as R;
    case "no-response":
      return {} as R;
    case "next-step":
    case "in-flight":
      throw new TrustTaskPending(reply);
    default:
      throw new TrustTaskError(reply.status, reply.document ?? reply.text ?? "", reply);
  }
}

/** The code a client reports for a reply that is not a success. */
export function replyCode(reply: Reply): string | undefined {
  if (reply.kind === "response" || reply.kind === "no-response") return undefined;
  if (reply.kind === "error") return reply.code;
  if (reply.kind === "next-step") return "nextStep";
  if (reply.kind === "in-flight") return "inFlight";
  return reply.code ?? (reply.text !== undefined ? "unreadable" : "unexpectedReply");
}

/**
 * True when an error says the thing a create/grant asked for is already there, by CODE: the VTA answers a duplicate
 * create with `taskFailed` and `details.reason: "conflict"` (vta-service `app_error_to_reject`), and a task may define
 * its own `<slug>:alreadyExists`. Never `idConflict`: that is a reused document id with different content (SPEC 8.3),
 * not an existing resource, and never a match on the human `message` (non-normative, SPEC 8.2.1).
 */
export function isAlreadyExists(body: unknown): boolean {
  const code = refusalCode(body);
  if (code === "taskFailed") return refusalDetails(body)?.reason === "conflict";
  return typeof code === "string" && /^[^:]+:alreadyExists$/.test(code);
}

/** True when an error says the consumer does not serve this type or version (the only reasons to try another version). */
export function isUnsupportedVersion(body: unknown): boolean {
  const code = refusalCode(body);
  return code === "unsupportedVersion" || code === "unsupportedType";
}

/**
 * The versions a consumer said it serves (`details.servedVersions` of an `unsupportedVersion`/`unsupportedType`
 * refusal), as `MAJOR.MINOR` strings; entries may be full Type URIs or bare versions. Undefined when it did not say.
 */
export function servedVersions(body: unknown): string[] | undefined {
  const v = refusalDetails(body)?.servedVersions;
  if (!Array.isArray(v)) return undefined;
  return v.filter((x): x is string => typeof x === "string").map((x) => x.match(/(\d+\.\d+)(?:#.*)?$/)?.[1] ?? x);
}
