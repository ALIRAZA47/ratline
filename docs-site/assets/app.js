/*
 * Ratline documentation site — behaviour.
 *
 * No dependencies, no build step, no module imports: this file is loaded with a
 * plain <script defer> tag so the site opens from file:// as well as over http.
 *
 * Four jobs:
 *   1. mark the rail item for the page you are on
 *   2. give every h2 and h3 with an id a copyable anchor
 *   3. search, over a static index declared below
 *   4. filter the long tables in place, and switch theme
 *
 * The search index is hand-written and lists only sections that exist. It is
 * checked by `verifyIndex()` at the bottom, which logs a warning if an entry
 * points at an anchor missing from the page it is currently on.
 */

(function () {
  "use strict";

  /* ---------------------------------------------------------------------- */
  /* Search index                                                          */
  /* ---------------------------------------------------------------------- */

  var INDEX = [
    // --- Overview
    { p: "index.html", t: "What Ratline is", h: "what-it-is", k: "problem positioning coolify forge moss dokploy self-hosted control plane" },
    { p: "index.html", t: "The two differentiators", h: "differentiators", k: "privilege authorization data layer" },
    { p: "index.html", t: "In scope for phase 1", h: "scope", k: "static sites node bun runtimes vite astro next nuxt hugo" },
    { p: "index.html", t: "Out of scope for v1", h: "out-of-scope", k: "docker kubernetes python php ruby billing multi-region email marketplace" },
    { p: "index.html", t: "Where the build stands", h: "status", k: "milestone progress tests coverage m1 m2 status dashboard" },
    { p: "index.html", t: "Vocabulary", h: "vocabulary", k: "glossary host site release deployment grant agent break-glass operation envelope" },
    { p: "index.html", t: "How to read this site", h: "where-to-start", k: "navigation order reviewer new engineer" },

    // --- Constraints
    { p: "constraints.html", t: "C1 — no root SSH to managed hosts", h: "c1", k: "coolify cvss 10 docker group root privilege" },
    { p: "constraints.html", t: "C2 — no shell built by interpolation", h: "c2", k: "argv injection sh -c fuzz lint" },
    { p: "constraints.html", t: "C3 — authorization at the data layer", h: "c3", k: "idor findbyid tenant scoping rls repository" },
    { p: "constraints.html", t: "C4 — no default secrets", h: "c4", k: "cloudpanel cve-2023-35885 cookie secret signing key first run" },
    { p: "constraints.html", t: "C5 — the dashboard is not internet-exposed", h: "c5", k: "loopback tailscale vpn allowlist 52000 exposure" },
    { p: "constraints.html", t: "C6 — every privileged action is attributable", h: "c6", k: "audit actor service identity" },
    { p: "constraints.html", t: "Constraint-to-threat trace", h: "trace", k: "table evidence enforcement threat model" },

    // --- Architecture
    { p: "architecture.html", t: "Components and their privilege", h: "components", k: "control plane postgres agent privd site process cli" },
    { p: "architecture.html", t: "Two listeners, two exposure policies", h: "deployment-shape", k: "dashboard agent endpoint mtls loopback" },
    { p: "architecture.html", t: "System diagram", h: "system", k: "diagram flow host dials out" },
    { p: "architecture.html", t: "Trust boundaries B1–B8", h: "boundaries", k: "b1 b2 b3 b4 b5 b6 b7 b8 hostile distrust proof" },
    { p: "architecture.html", t: "Data model", h: "data-model", k: "organization team project environment site release grant audit entry secret version" },
    { p: "architecture.html", t: "Repository layout", h: "layout", k: "src db internal repo authz api jobs crypto ops web agent test" },
    { p: "architecture.html", t: "Stack, and where it was argued", h: "stack", k: "typescript hono node 22 postgres 17 react go drizzle vite" },

    // --- Authorization
    { p: "authorization.html", t: "The permission catalogue", h: "catalogue", k: "106 actions resource types scope levels secret read_name read_value" },
    { p: "authorization.html", t: "The seven default roles", h: "roles", k: "owner admin infrastructure release manager developer viewer billing" },
    { p: "authorization.html", t: "can() — one decision function", h: "can", k: "deny by default decision reason branch coverage api token ceiling" },
    { p: "authorization.html", t: "Three layers of tenant isolation", h: "isolation", k: "handle branded authzcontext forced row level security" },
    { p: "authorization.html", t: "Why there is no authorization middleware", h: "no-middleware", k: "nine ungated repository reads audit log middleware masked" },
    { p: "authorization.html", t: "The route table", h: "routes", k: "30 routes public reason guarded scope source data" },
    { p: "authorization.html", t: "The authorization matrix", h: "matrix", k: "630 cells transport decision declaration honest split" },

    // --- Agent protocol
    { p: "agent.html", t: "The signed instruction envelope", h: "envelope", k: "operation arguments nonce issued_at expires_at target_host_id ed25519" },
    { p: "agent.html", t: "The signature is not over the JSON", h: "canonical-bytes", k: "canonical length-prefixed domain separation injective" },
    { p: "agent.html", t: "The verification order is the security property", h: "order", k: "signature target expiry nonce catalogue arguments" },
    { p: "agent.html", t: "The operation catalogue", h: "operations", k: "13 operations idempotent performer agent privd" },
    { p: "agent.html", t: "The argument-kind vocabulary", h: "kinds", k: "13 kinds pattern re2 validator systemd nginx visudo x509 pkcs8 no free-form command" },
    { p: "agent.html", t: "The privileged helper", h: "privd", k: "root socket activated so_peercred re-validate append-only log" },

    // --- Threat model
    { p: "threat-model.html", t: "Assets, ranked", h: "assets", k: "ssh authority instruction signing secret wrapping crown jewels" },
    { p: "threat-model.html", t: "Actors", h: "actors", k: "owner admin infrastructure developer viewer billing service identity external" },
    { p: "threat-model.html", t: "Compromised agent", h: "agent-compromise", k: "unprivileged secrets false inventory r-07" },
    { p: "threat-model.html", t: "Compromised control plane", h: "control-plane-compromise", k: "signing key certificates fleet unprivileged code execution" },
    { p: "threat-model.html", t: "Compromised low-privilege account", h: "account-compromise", k: "developer build command lateral sandbox escape r-05" },
    { p: "threat-model.html", t: "Crown-jewel key handling", h: "keys", k: "generated stored rotation compromise recovery" },
    { p: "threat-model.html", t: "Attack surface inventory", h: "surface", k: "dashboard agent endpoint webhook privd socket sshd object storage" },
    { p: "threat-model.html", t: "Risk register", h: "risks", k: "r-01 r-02 r-05 r-08 r-14 r-30 open closed owner" },

    // --- Decisions
    { p: "decisions.html", t: "All 18 decision records", h: "adrs", k: "adr table proposed accepted status" },
    { p: "decisions.html", t: "Why none is accepted", h: "status-note", k: "brief 2.6 owner acceptance authorizations a-01" },
    { p: "decisions.html", t: "ADR 0001 — Stack choice", h: "adr-0001", k: "typescript hono node react postgres go" },
    { p: "decisions.html", t: "ADR 0002 — Agent transport and authentication", h: "adr-0002", k: "mtls envelope catalogue bootstrap ssh nonce rotation" },
    { p: "decisions.html", t: "ADR 0003 — Tenant scoping and data access", h: "adr-0003", k: "three layers handle branded context rls" },
    { p: "decisions.html", t: "ADR 0004 — Host privilege separation", h: "adr-0004", k: "privd root socket peercred revalidate" },
    { p: "decisions.html", t: "ADR 0005 — Command execution and build scripts", h: "adr-0005", k: "c2 build command file argv sandbox permission" },
    { p: "decisions.html", t: "ADR 0006 — Secrets and envelope encryption", h: "adr-0006", k: "data key aead wrapping redaction streaming" },
    { p: "decisions.html", t: "ADR 0007 — Job queue on Postgres", h: "adr-0007", k: "skip locked listen notify dead letter no redis" },
    { p: "decisions.html", t: "ADR 0008 — SSH certificate authority", h: "adr-0008", k: "certificates principals revocation sudoers web terminal" },
    { p: "decisions.html", t: "ADR 0009 — Where builds run", h: "adr-0009", k: "target host transient scope limits cache" },
    { p: "decisions.html", t: "ADR 0010 — Web server config generation", h: "adr-0010", k: "template escaper stage validate snapshot swap reload verify roll back" },
    { p: "decisions.html", t: "ADR 0011 — Exposure detection without phoning home", h: "adr-0011", k: "classify locally contained network exposed wildcard" },
    { p: "decisions.html", t: "ADR 0012 — Grant resolution and the expiry clock", h: "adr-0012", k: "live_grants effective_grants grant_decision security invoker check" },
    { p: "decisions.html", t: "ADR 0013 — Managed database engines", h: "adr-0013", k: "m7 postgres mysql mongodb backup restore first sspl" },
    { p: "decisions.html", t: "ADR 0014 — Sessions and password storage", h: "adr-0014", k: "scrypt rotation absolute lifetime hashed token" },
    { p: "decisions.html", t: "ADR 0015 — Authentication rate limiting", h: "adr-0015", k: "account address budget window statement_timestamp" },
    { p: "decisions.html", t: "ADR 0016 — CSRF tokens and cookie policy", h: "adr-0016", k: "derived token header samesite secure host prefix origin" },
    { p: "decisions.html", t: "ADR 0017 — Session idle timeout", h: "adr-0017", k: "no idle timeout reauthentication screen lock" },
    { p: "decisions.html", t: "ADR 0018 — Two-factor authentication", h: "adr-0018", k: "totp challenge recovery codes webauthn gap" },

    // --- Roadmap
    { p: "roadmap.html", t: "Milestones M0–M7", h: "milestones", k: "plan control plane agent static sites node bun rbac ssh databases" },
    { p: "roadmap.html", t: "Task counts by milestone", h: "counts", k: "todo review done high risk tracker" },
    { p: "roadmap.html", t: "M1 — Control plane skeleton", h: "m1", k: "exit criteria matrix harness tasks validate" },
    { p: "roadmap.html", t: "M2 — Agent and first host", h: "m2", k: "debian idempotent zero root ssh in progress" },

    // --- Workflow
    { p: "workflow.html", t: "The tracking system", h: "tracking", k: "tasks.yaml cli validate render definition of ready progress" },
    { p: "workflow.html", t: "Running it locally", h: "local", k: "pg migrate preflight host agent node 22 postgres 55432" },
    { p: "workflow.html", t: "The CI pipeline", h: "ci", k: "tracker code database agent status five jobs postgres 17" },
    { p: "workflow.html", t: "Gates that fail on absent coverage", h: "gates", k: "coverage 100 percent authz can branch absent" },
    { p: "workflow.html", t: "Mutation testing as practice", h: "mutation", k: "break a property escaped mutation three" },
    { p: "workflow.html", t: "Commit and branch conventions", h: "conventions", k: "branch per task commit subject acceptance risk" },

    // --- Defects
    { p: "defects.html", t: "Outstanding at the M1 gate", h: "outstanding", k: "rl-m1-020 rl-m1-046 rl-m1-049 rl-m1-050 review todo" },
    { p: "defects.html", t: "Four defects that were invisible while green", h: "invisible-defects", k: "scratch database collision cluster state regression ci-metrics names" },
    { p: "defects.html", t: "Open questions the owner holds", h: "open-questions", k: "r-02 r-08 m7 scope threat model public adr acceptance" },
    { p: "defects.html", t: "Where the documents disagree", h: "contradictions", k: "stale numbers 567 cells 27 routes readme 602 tests known gaps" }
  ];

  var PAGE_TITLES = {
    "index.html": "Overview",
    "constraints.html": "Constraints",
    "architecture.html": "Architecture",
    "authorization.html": "Authorization",
    "agent.html": "Agent protocol",
    "threat-model.html": "Threat model",
    "decisions.html": "Decisions",
    "roadmap.html": "Roadmap",
    "workflow.html": "Workflow",
    "defects.html": "Defects"
  };

  /* ---------------------------------------------------------------------- */
  /* Helpers                                                               */
  /* ---------------------------------------------------------------------- */

  function currentPage() {
    var parts = window.location.pathname.split("/");
    var last = parts[parts.length - 1];
    return last === "" ? "index.html" : last;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* ---------------------------------------------------------------------- */
  /* 1. Rail: mark the current page                                        */
  /* ---------------------------------------------------------------------- */

  function markRail(page) {
    var links = document.querySelectorAll(".rail__link");
    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute("href") || "";
      if (href.split("#")[0] === page) {
        links[i].setAttribute("aria-current", "page");
      } else {
        links[i].removeAttribute("aria-current");
      }
    }
  }

  /* ---------------------------------------------------------------------- */
  /* 2. Heading anchors                                                    */
  /* ---------------------------------------------------------------------- */

  function addAnchors() {
    var heads = document.querySelectorAll("main h2[id], main h3[id]");
    for (var i = 0; i < heads.length; i++) {
      var id = heads[i].id;
      var a = el("a", "anchor", "#");
      a.href = "#" + id;
      a.setAttribute("aria-label", "Link to this section: " + heads[i].textContent.trim());
      heads[i].appendChild(a);
    }
  }

  /* ---------------------------------------------------------------------- */
  /* 3. Search                                                             */
  /* ---------------------------------------------------------------------- */

  function setupSearch(page) {
    var input = document.getElementById("site-search");
    var list = document.getElementById("site-search-results");
    if (!input || !list) return;

    var active = -1;
    var shown = [];

    function close() {
      list.hidden = true;
      list.textContent = "";
      active = -1;
      shown = [];
    }

    function score(entry, terms) {
      var haystack = (entry.t + " " + entry.k + " " + PAGE_TITLES[entry.p]).toLowerCase();
      var total = 0;
      for (var i = 0; i < terms.length; i++) {
        var at = haystack.indexOf(terms[i]);
        if (at < 0) return -1;
        total += at === 0 ? 3 : 1;
        if (entry.t.toLowerCase().indexOf(terms[i]) >= 0) total += 4;
      }
      return total;
    }

    function render(query) {
      var terms = query.toLowerCase().split(/\s+/).filter(function (t) { return t.length > 0; });
      if (terms.length === 0) { close(); return; }

      var hits = [];
      for (var i = 0; i < INDEX.length; i++) {
        var s = score(INDEX[i], terms);
        if (s >= 0) hits.push({ entry: INDEX[i], score: s });
      }
      hits.sort(function (a, b) { return b.score - a.score; });
      hits = hits.slice(0, 12);

      list.textContent = "";
      shown = [];

      if (hits.length === 0) {
        var none = el("li", "search__empty",
          "Nothing matches “" + query + "”. Try a constraint (C3), a risk (R-08), an ADR number, or a term such as envelope, matrix or privd.");
        list.appendChild(none);
        list.hidden = false;
        return;
      }

      for (var j = 0; j < hits.length; j++) {
        var e = hits[j].entry;
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.href = (e.p === page ? "" : e.p) + "#" + e.h;
        a.appendChild(el("span", null, e.t));
        a.appendChild(el("span", "where", PAGE_TITLES[e.p]));
        li.appendChild(a);
        list.appendChild(li);
        shown.push(a);
      }
      active = -1;
      list.hidden = false;
    }

    function move(delta) {
      if (shown.length === 0) return;
      active += delta;
      if (active < 0) active = shown.length - 1;
      if (active >= shown.length) active = 0;
      shown[active].focus();
    }

    input.addEventListener("input", function () { render(input.value); });

    input.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { close(); input.blur(); }
      else if (event.key === "ArrowDown") { event.preventDefault(); move(1); }
      else if (event.key === "ArrowUp") { event.preventDefault(); move(-1); }
      else if (event.key === "Enter" && shown.length > 0) {
        event.preventDefault();
        shown[0].click();
      }
    });

    list.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { close(); input.focus(); }
      else if (event.key === "ArrowDown") { event.preventDefault(); move(1); }
      else if (event.key === "ArrowUp") { event.preventDefault(); move(-1); }
    });

    document.addEventListener("click", function (event) {
      if (!list.hidden && !list.contains(event.target) && event.target !== input) close();
    });

    document.addEventListener("keydown", function (event) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if ((event.key === "k" || event.key === "K") && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        input.focus();
        input.select();
      } else if (event.key === "/" && !typing) {
        event.preventDefault();
        input.focus();
      }
    });
  }

  /* ---------------------------------------------------------------------- */
  /* 4. Table filters                                                      */
  /* ---------------------------------------------------------------------- */

  function setupFilters() {
    var inputs = document.querySelectorAll("[data-filter-for]");
    for (var i = 0; i < inputs.length; i++) {
      wireFilter(inputs[i]);
    }
  }

  function wireFilter(input) {
    var table = document.getElementById(input.getAttribute("data-filter-for"));
    if (!table) return;
    var rows = table.tBodies.length ? table.tBodies[0].rows : [];
    var counter = document.getElementById(input.getAttribute("data-filter-count") || "");
    var empty = document.getElementById(input.getAttribute("data-filter-empty") || "");
    var total = rows.length;

    function apply() {
      var terms = input.value.toLowerCase().split(/\s+/).filter(function (t) { return t.length > 0; });
      var visible = 0;
      for (var i = 0; i < rows.length; i++) {
        var text = (rows[i].textContent || "").toLowerCase();
        var ok = true;
        for (var j = 0; j < terms.length; j++) {
          if (text.indexOf(terms[j]) < 0) { ok = false; break; }
        }
        rows[i].hidden = !ok;
        if (ok) visible++;
      }
      if (counter) {
        counter.textContent = visible === total
          ? String(total) + " rows"
          : String(visible) + " of " + String(total) + " rows";
      }
      if (empty) {
        empty.hidden = visible !== 0;
        if (visible === 0) {
          empty.textContent = "No row matches “" + input.value + "”. Clear the filter to see all "
            + String(total) + " rows.";
        }
      }
    }

    input.addEventListener("input", apply);
    input.addEventListener("search", apply);
    apply();
  }

  /* ---------------------------------------------------------------------- */
  /* 5. Theme                                                              */
  /* ---------------------------------------------------------------------- */

  var THEME_KEY = "ratline-docs-theme";

  function readStored() {
    try { return window.localStorage.getItem(THEME_KEY); } catch (e) { return null; }
  }
  function writeStored(value) {
    try {
      if (value === null) window.localStorage.removeItem(THEME_KEY);
      else window.localStorage.setItem(THEME_KEY, value);
    } catch (e) { /* file:// may refuse storage; the toggle still works per page. */ }
  }

  function applyTheme(value, button) {
    if (value === "light" || value === "dark") {
      document.documentElement.setAttribute("data-theme", value);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
    if (button) {
      var label = value === "light" ? "Light" : value === "dark" ? "Dark" : "System";
      button.textContent = "Theme: " + label;
      button.setAttribute("aria-label", "Change theme. Currently " + label.toLowerCase() + ".");
    }
  }

  function setupTheme() {
    var button = document.getElementById("theme-toggle");
    var stored = readStored();
    applyTheme(stored, button);
    if (!button) return;
    button.addEventListener("click", function () {
      var order = [null, "light", "dark"];
      var now = readStored();
      var next = order[(order.indexOf(now === "light" || now === "dark" ? now : null) + 1) % order.length];
      writeStored(next);
      applyTheme(next, button);
    });
  }

  /* ---------------------------------------------------------------------- */
  /* 6. Index self-check                                                   */
  /* ---------------------------------------------------------------------- */

  function verifyIndex(page) {
    var missing = [];
    for (var i = 0; i < INDEX.length; i++) {
      if (INDEX[i].p !== page) continue;
      if (!document.getElementById(INDEX[i].h)) missing.push(INDEX[i].h);
    }
    if (missing.length > 0) {
      window.console.warn("Search index names anchors this page does not have: " + missing.join(", "));
    }
  }

  /* ---------------------------------------------------------------------- */

  function start() {
    var page = currentPage();
    markRail(page);
    addAnchors();
    setupSearch(page);
    setupFilters();
    setupTheme();
    verifyIndex(page);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
