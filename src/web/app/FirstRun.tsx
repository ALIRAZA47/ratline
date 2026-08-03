/**
 * First run and sign-in (RL-M1-030).
 *
 * Two forms and one decision between them: `GET /bootstrap` says whether this
 * installation has been claimed, and the operator sees exactly one of them. An
 * unclaimed installation showing a sign-in form is a dead end — there are no
 * accounts to sign in to — and a claimed one showing a claim form invites
 * somebody to try.
 *
 * ## The copy, per brief §291
 *
 * "Active voice, plain nouns from the operator's world, buttons named for what
 * happens. Errors state what broke and what to do next. Empty states invite
 * action rather than apologise."
 *
 * So the button says "Claim this installation", not "Submit". The token field
 * explains where to find the token rather than assuming the operator knows. And
 * the sign-in refusal says one thing for every cause, because §6.3 requires it:
 * "unknown account" and "wrong password" must be indistinguishable, and a form
 * that helpfully distinguished them would be an account oracle.
 *
 * Nothing here decides anything. The claim is validated server-side by
 * `validateInstallation` and gated by the bootstrap token; this only renders
 * what the server says, so a form field cannot become a second opinion about
 * what a valid claim is.
 */

import { useEffect, useState, type CSSProperties, type ReactNode } from "react";

const field: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: "var(--space-xxs)",
  font: "var(--weight-body) var(--text-sm)/var(--leading-sm) var(--font-body)",
  color: "var(--chalk-dim)",
};

const input: CSSProperties = {
  background: "var(--tar)",
  border: "var(--hairline-width) solid var(--rule-hairline)",
  borderRadius: "var(--radius-sm)",
  color: "var(--chalk)",
  padding: "var(--space-xs) var(--space-sm)",
  font: "var(--weight-body) var(--text-base)/var(--leading-base) var(--font-body)",
};

const button: CSSProperties = {
  background: "var(--hemp)",
  border: "none",
  borderRadius: "var(--radius-sm)",
  color: "var(--tar)",
  padding: "var(--space-sm) var(--space-md)",
  font: "var(--weight-body-strong) var(--text-base)/var(--leading-base) var(--font-body)",
  cursor: "pointer",
};

function Panel({ title, lede, children }: { title: string; lede: string; children: ReactNode }): React.JSX.Element {
  return (
    <main
      style={{
        minHeight: "100vh",
        background: "var(--tar)",
        color: "var(--chalk)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "var(--space-lg)",
      }}
    >
      <div style={{ width: "min(30rem, 100%)", display: "flex", flexDirection: "column", gap: "var(--space-md)" }}>
        <h1
          style={{
            margin: 0,
            font: "var(--weight-display) var(--text-xl)/var(--leading-xl) var(--font-display)",
            fontStretch: "var(--display-stretch)",
          }}
        >
          {title}
        </h1>
        <p style={{ margin: 0, color: "var(--chalk-dim)", font: "var(--weight-body) var(--text-base)/var(--leading-base) var(--font-body)" }}>
          {lede}
        </p>
        {children}
      </div>
    </main>
  );
}

/** Whatever the server said went wrong, rendered as the server worded it. */
function Problems({ problems }: { readonly problems: readonly string[] }): React.JSX.Element | null {
  if (problems.length === 0) return null;
  return (
    <ul
      role="alert"
      style={{
        margin: 0,
        padding: "var(--space-sm) var(--space-md)",
        listStyle: "disc inside",
        border: "var(--hairline-width) solid var(--st-attention)",
        borderRadius: "var(--radius-sm)",
        color: "var(--st-attention)",
        font: "var(--weight-body) var(--text-sm)/var(--leading-sm) var(--font-body)",
      }}
    >
      {problems.map((problem) => (
        <li key={problem}>{problem}</li>
      ))}
    </ul>
  );
}

export function ClaimForm(): React.JSX.Element {
  const [problems, setProblems] = useState<readonly string[]>([]);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    // FormData can hold a File, which would stringify to "[object Object]".
    // Read text fields as text explicitly rather than coercing whatever is
    // there — a token that silently became "[object Object]" would fail with a
    // message about the token being wrong, which is true and useless.
    const text = (name: string): string => {
      const value = form.get(name);
      return typeof value === "string" ? value : "";
    };

    const response = await fetch("/bootstrap", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-ratline-bootstrap": text("token"),
      },
      body: JSON.stringify({
        organizationSlug: text("slug"),
        organizationName: text("name"),
        ownerEmail: text("email"),
        ownerName: text("owner"),
        ownerPassword: text("password"),
      }),
    });
    setBusy(false);

    if (response.status === 201) {
      globalThis.location.assign("/");
      return;
    }
    if (response.status === 422) {
      const body = (await response.json()) as { problems?: string[] };
      setProblems(body.problems ?? []);
      return;
    }
    // One message for every other refusal — wrong token, already claimed,
    // missing token. Distinguishing them would tell an unauthenticated caller
    // whether this installation is worth attacking.
    setProblems([
      "That token was not accepted. Read the current one from bootstrap.token in the secrets directory on the server.",
    ]);
  }

  return (
    <Panel
      title="Claim this installation"
      lede="Nothing has been set up here yet. Create the first organization and the owner who will run it."
    >
      <form onSubmit={(e) => void onSubmit(e)} style={{ display: "flex", flexDirection: "column", gap: "var(--space-sm)" }}>
        <Problems problems={problems} />
        <label style={field}>
          Bootstrap token
          <input name="token" required autoComplete="off" style={input} />
          <span>Printed on first boot, and readable at bootstrap.token in the secrets directory.</span>
        </label>
        <label style={field}>
          Organization name
          <input name="name" required placeholder="Acme Rigging" style={input} />
        </label>
        <label style={field}>
          Short name
          <input name="slug" required placeholder="acme" style={input} />
          <span>Lower-case letters, digits and hyphens. It appears in URLs.</span>
        </label>
        <label style={field}>
          Your name
          <input name="owner" required style={input} />
        </label>
        <label style={field}>
          Your email
          <input name="email" type="email" required autoComplete="username" style={input} />
        </label>
        <label style={field}>
          Password
          <input name="password" type="password" required autoComplete="new-password" style={input} />
          <span>At least 12 characters. A passphrase of four words beats a short scramble.</span>
        </label>
        <button type="submit" disabled={busy} style={button}>
          {busy ? "Claiming…" : "Claim this installation"}
        </button>
      </form>
    </Panel>
  );
}

export function SignInForm(): React.JSX.Element {
  const [problems, setProblems] = useState<readonly string[]>([]);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    const form = new FormData(event.currentTarget);
    const response = await fetch("/auth/sign-in", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: typeof form.get("email") === "string" ? form.get("email") : "",
        password: typeof form.get("password") === "string" ? form.get("password") : "",
      }),
    });
    setBusy(false);

    if (response.ok) {
      globalThis.location.assign("/");
      return;
    }
    // ONE message, whatever the reason. §6.3 requires an unknown account and a
    // wrong password to be indistinguishable, and a form that helpfully told
    // them apart would be the account oracle the whole rule exists to close.
    // The rate limiter's refusal lands here too, for the same reason.
    setProblems(["That email and password did not match. Check both, then try again."]);
  }

  return (
    <Panel title="Sign in" lede="This installation is already set up.">
      <form onSubmit={(e) => void onSubmit(e)} style={{ display: "flex", flexDirection: "column", gap: "var(--space-sm)" }}>
        <Problems problems={problems} />
        <label style={field}>
          Email
          <input name="email" type="email" required autoComplete="username" style={input} />
        </label>
        <label style={field}>
          Password
          <input name="password" type="password" required autoComplete="current-password" style={input} />
        </label>
        <button type="submit" disabled={busy} style={button}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </Panel>
  );
}

/**
 * Which of the two to show.
 *
 * Null while the answer is unknown — rendering the sign-in form and swapping it
 * for the claim form a moment later would be the flicker §4 is written against,
 * and worse: an operator who started typing into the wrong one loses it.
 */
export function Entry(): React.JSX.Element | null {
  const [unclaimed, setUnclaimed] = useState<boolean | null>(null);

  useEffect(() => {
    void fetch("/bootstrap")
      .then((response) => response.json() as Promise<{ unclaimed: boolean }>)
      .then((body) => { setUnclaimed(body.unclaimed); })
      // A server that cannot answer is not an unclaimed one. Failing closed here
      // means showing the sign-in form, which is useless on a fresh install and
      // harmless on a live one — the other way round invites a claim attempt.
      .catch(() => { setUnclaimed(false); });
  }, []);

  if (unclaimed === null) return null;
  return unclaimed ? <ClaimForm /> : <SignInForm />;
}
