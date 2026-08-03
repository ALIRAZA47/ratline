/**
 * The command palette (RL-M1-029).
 *
 * DESIGN.md §8: "The command palette is the keyboard route to every action, and
 * it lists only actions the current actor may take."
 *
 * ## Generated from the catalogue, and why that is the whole task
 *
 * The acceptance says "generated from the same action catalogue the permission
 * system uses", and the alternative is worth naming because it is what almost
 * every product does: a hand-written list of commands. That list is a second
 * enumeration of what the product can do, and it drifts in both directions.
 * Missing an entry makes a capability unreachable by keyboard, which is a
 * usability bug. Keeping an entry after the action is gone offers somebody a
 * command that cannot work — and worse, an entry written by hand can carry the
 * WRONG required permission, which means the palette shows a privileged command
 * to somebody who cannot run it. That last one is the acceptance's third
 * criterion, and a hand-written list is exactly how it happens.
 *
 * So there is no list here. Every command is an `Action` from the catalogue,
 * and its required permission is itself. That is not a simplification — it is
 * what makes the filter checkable: `visibleCommands` cannot show a command
 * whose permission the actor lacks, because the command IS the permission.
 *
 * ## This is not an authorization check
 *
 * Said in the same words as the navigation rail, because the mistake is the
 * same one. `can()` at the data layer is the only thing that refuses anything
 * (C3, §9). The palette hiding a command is a courtesy to the operator, not a
 * control; running the command still goes through the repository, which still
 * asks. If this file were the only thing standing between a Developer and
 * `secret.read_value`, the product would be broken in a way no test here could
 * detect.
 */

import {
  ACTION_CATALOGUE,
  ALL_ACTIONS,
  type Action,
  type ResourceType,
} from "../../../authz/catalogue.ts";

export type Command = {
  /** The action, which is also the permission required to run it. */
  readonly action: Action;
  readonly resource: ResourceType;
  /** What an operator reads. The catalogue's own description, never a second copy. */
  readonly description: string;
  /**
   * What is typed to find it.
   *
   * The action name with its separators opened up, so `secret.read_value`
   * matches "secret", "read" and "value" — an operator hunting for "read
   * secret" should not have to know the punctuation.
   */
  readonly terms: readonly string[];
};

function termsFor(action: Action): string[] {
  return [action, ...action.split(/[._]/)].filter((term) => term.length > 0);
}

/**
 * Every command the product has, in catalogue order.
 *
 * Derived, so an action added to the catalogue is in the palette in the same
 * commit — and an action removed from it cannot linger here.
 */
export const ALL_COMMANDS: readonly Command[] = ALL_ACTIONS.map((action) => ({
  action,
  resource: ACTION_CATALOGUE[action].resource,
  description: ACTION_CATALOGUE[action].description,
  terms: termsFor(action),
}));

/**
 * The commands an actor holding `held` may run.
 *
 * A courtesy filter, not a control — see the module header. Written as "show
 * what is held" rather than "hide what is denied" so that an actor holding
 * nothing sees nothing; the other phrasing shows everything to somebody with no
 * grants, and passes every test that only checks a restricted role.
 */
export function visibleCommands(
  held: readonly string[],
  commands: readonly Command[] = ALL_COMMANDS,
): Command[] {
  return commands.filter((command) => held.includes(command.action));
}

/**
 * Rank matches for a typed query.
 *
 * Prefix beats substring, and an earlier match beats a later one. Nothing
 * cleverer: a fuzzy matcher that reorders results as you type is disorienting
 * in a tool people reach for during an incident, which is §6.6's whole
 * complaint about interfaces that feel like websites.
 *
 * An empty query returns everything, in catalogue order, rather than nothing.
 * The palette opens before anything is typed and an empty palette reads as
 * broken.
 */
export function searchCommands(query: string, commands: readonly Command[]): Command[] {
  const needle = query.trim().toLowerCase();
  if (needle === "") return [...commands];

  const scored: { command: Command; score: number }[] = [];
  for (const command of commands) {
    let best = Number.POSITIVE_INFINITY;
    for (const term of command.terms) {
      const at = term.toLowerCase().indexOf(needle);
      if (at === -1) continue;
      // A prefix match on any term scores 0; otherwise the offset, so a match
      // near the start of a word ranks above one buried in it.
      best = Math.min(best, at);
    }
    // The description is searched too, and always ranks below a name match: an
    // operator typing "secret" wants the secret actions, not every action whose
    // description happens to mention one.
    if (best === Number.POSITIVE_INFINITY && command.description.toLowerCase().includes(needle)) {
      best = 1000;
    }
    if (best !== Number.POSITIVE_INFINITY) scored.push({ command, score: best });
  }

  // Stable within a score, so equal matches keep catalogue order rather than
  // shuffling as unrelated actions are added.
  return scored
    .map((entry, index) => ({ ...entry, index }))
    .sort((a, b) => a.score - b.score || a.index - b.index)
    .map((entry) => entry.command);
}

/**
 * Group commands by the thing they act on, for rendering.
 *
 * Preserves catalogue order within a group and orders the groups by first
 * appearance, so the palette's shape is the catalogue's shape and nobody has to
 * maintain a second opinion about which resources matter.
 */
export function groupCommands(commands: readonly Command[]): { resource: ResourceType; commands: Command[] }[] {
  const groups = new Map<ResourceType, Command[]>();
  for (const command of commands) {
    const existing = groups.get(command.resource);
    if (existing === undefined) groups.set(command.resource, [command]);
    else existing.push(command);
  }
  return [...groups].map(([resource, grouped]) => ({ resource, commands: grouped }));
}
