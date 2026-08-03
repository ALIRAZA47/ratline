/**
 * The scheduled audit verification job (RL-M1-015).
 *
 * Brief §6.3: "Chain verification is a scheduled job."
 *
 * Two properties matter more than the scheduling itself:
 *
 *   1. A BROKEN OR TRUNCATED CHAIN RAISES, IT DOES NOT LOG.
 *      A verification job that writes a line and returns zero is a job whose
 *      failures nobody sees. The whole point of the audit log is to be trusted
 *      during an incident, and a chain that quietly stopped verifying three
 *      weeks ago is worse than no chain at all — it is a chain someone will
 *      rely on. So the run reports its findings to a handler that must exist.
 *
 *   2. THE JOB ITSELF IS ATTRIBUTED (C6).
 *      It runs as a named service identity through `contextForSystem`, not as
 *      an anonymous background task. The audit log records who verified it, and
 *      "the system" is not an acceptable answer to that question.
 *
 * The job is deliberately not a scheduler. Scheduling is the queue's job
 * (ADR 0007); this is the unit of work it runs, which makes it testable without
 * waiting for a timer.
 */

import { contextForSystem, type AuthzContext } from "../authz/context.ts";
import { recordAudit } from "../repo/audit.ts";
import { runAuditVerification, type VerificationResult } from "../repo/audit_verification.ts";

export type VerificationAlert = {
  readonly orgId: string;
  readonly outcome: "broken" | "truncated";
  readonly detail: string;
  readonly headSeq: string;
};

export type VerificationJobOptions = {
  /**
   * Where a failed verification goes. Required, with no default.
   *
   * A default that logged would make the alert path optional in practice, and
   * the first deployment to forget it would discover the omission only when it
   * mattered. RL-M3-025 supplies the real notification destinations; until then
   * a caller passes something that at minimum makes noise.
   */
  readonly onAlert: (alert: VerificationAlert) => Promise<void> | void;
};

export type VerificationJobResult = {
  readonly orgId: string;
  readonly result: VerificationResult;
  readonly alerted: boolean;
};

/**
 * Verify one tenant's chain, record the result in the audit log, and alert if
 * it is not clean.
 *
 * The audit entry is written for every outcome including a clean one. A log
 * that records only failures cannot answer "when was this last checked", which
 * is the question asked first during an incident.
 */
export async function verifyAuditChainForTenant(
  ctx: AuthzContext,
  options: VerificationJobOptions,
): Promise<VerificationJobResult> {
  const result = await runAuditVerification(ctx);

  await recordAudit(ctx, {
    action: "audit_log.read",
    resourceType: "audit_log",
    decision: "allow",
    reason: `chain verification: ${result.outcome}`,
    metadata: {
      outcome: result.outcome,
      head_seq: result.headSeq,
      // The detail names a sequence number and a reason, never any entry's
      // contents — this metadata is itself in the audit log.
      detail: result.detail,
    },
  });

  if (result.outcome === "clean") {
    return { orgId: ctx.orgId, result, alerted: false };
  }

  await options.onAlert({
    orgId: ctx.orgId,
    outcome: result.outcome,
    detail: result.detail,
    headSeq: result.headSeq,
  });

  // Raising after alerting is deliberate: the alert is the useful part, and it
  // must happen even though the job is about to fail. Failing loudly then stops
  // the run being recorded as a success by whatever ran it.
  throw new AuditChainCompromised(ctx.orgId, result);
}

/**
 * Thrown when a chain does not verify.
 *
 * A distinct type so a caller can tell "the audit log is compromised" from
 * "the database was unreachable" — those need different responses at 2am.
 */
export class AuditChainCompromised extends Error {
  readonly orgId: string;
  readonly result: VerificationResult;

  constructor(orgId: string, result: VerificationResult) {
    super(
      `audit chain for organization ${orgId} is ${result.outcome}: ${result.detail}. ` +
        `The audit log can no longer be trusted as evidence until this is explained.`,
    );
    this.name = "AuditChainCompromised";
    this.orgId = orgId;
    this.result = result;
  }
}

/**
 * Build the context this job runs under.
 *
 * Separate and exported so a caller cannot construct an unattributed one by
 * accident — `contextForSystem` refuses a purpose outside the enumerated list,
 * and this is the only purpose that applies here.
 */
export function verificationContext(input: {
  readonly orgId: string;
  readonly serviceIdentityId: string;
  readonly requestId: string;
}): AuthzContext {
  return contextForSystem({
    purpose: "audit-chain-verification",
    orgId: input.orgId,
    serviceIdentityId: input.serviceIdentityId,
    requestId: input.requestId,
  });
}
