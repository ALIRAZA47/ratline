/**
 * What the dashboard knows before it renders anything (RL-M1-058).
 *
 * The shell was built as chrome and rendered with placeholder data, so opening the
 * dashboard showed an empty frame around `marketing-www` — a site that does not
 * exist. This module is the one question that has to be answered before a frame is
 * worth drawing: is there a session, and if not, why not.
 *
 * ## Why `/organization` and not a dedicated endpoint
 *
 * The obvious design is `GET /session` returning who you are. It would also be a
 * second source of truth about authorization: an endpoint that says "you are signed
 * in" while the endpoint you actually need refuses you is worse than no answer,
 * because the interface would then show a shell it cannot fill.
 *
 * So the probe IS a real read. `GET /organization` is the least privileged thing every
 * signed-in actor can do — it resolves `organization.read`, which all seven roles
 * hold — so a 200 means "there is a session AND it can do the minimum", and a 401
 * means sign in. No inference, no second opinion.
 */

/** The exposure notice the server injected into the page, if it did. */
export type Exposure = {
  readonly level: string;
  readonly warning: string | null;
  readonly caveat: string | null;
};

export type Organization = {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
};

export type Entry =
  /** A session exists and can read its own organization. */
  | { readonly kind: "signed-in"; readonly organization: Organization }
  /** No session. The entry screens decide between claiming and signing in. */
  | { readonly kind: "signed-out" }
  /**
   * The server could not be asked. NOT the same as signed out, and rendering a
   * sign-in form here would invite an operator to type a password into a page that
   * cannot deliver it — which is how a transient outage becomes a credential typed
   * into something unknown.
   */
  | { readonly kind: "unreachable"; readonly detail: string };

/**
 * Ask the server where we stand.
 *
 * `credentials: "same-origin"` explicitly rather than by default, because the cookie
 * is the whole question and a default that changes between browsers is not something
 * this should depend on.
 */
export async function resolveEntry(): Promise<Entry> {
  let response: Response;
  try {
    response = await fetch("/organization", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
  } catch (cause) {
    return {
      kind: "unreachable",
      detail: cause instanceof Error ? cause.message : "the request failed",
    };
  }

  if (response.status === 401) return { kind: "signed-out" };

  if (response.status === 404) {
    // A refusal, not an absence. §6.3 makes unauthorized and nonexistent
    // indistinguishable on purpose, so the dashboard must not guess which it was —
    // and it does not need to: either way there is nothing here for this actor.
    return { kind: "signed-out" };
  }

  if (!response.ok) {
    return { kind: "unreachable", detail: `the server answered ${String(response.status)}` };
  }

  try {
    const organization = (await response.json()) as Organization;
    return { kind: "signed-in", organization };
  } catch {
    return { kind: "unreachable", detail: "the server's answer was not JSON" };
  }
}

/**
 * The exposure notice, read from the page rather than fetched.
 *
 * Injected into the served HTML by `src/api/dashboard.ts`, and that placement is the
 * decision. C5 wants a warning that cannot be dismissed, so it must survive the two
 * cases a fetch would not: before anyone signs in, and when the API is failing. A
 * warning that needs a working session to appear is a warning that is absent exactly
 * when somebody is most likely to be poking at an exposed dashboard.
 */
export function readExposure(): Exposure | null {
  const element = document.querySelector<HTMLScriptElement>("#ratline-exposure");
  if (element === null || element.textContent === null) return null;
  try {
    return JSON.parse(element.textContent) as Exposure;
  } catch {
    return null;
  }
}
