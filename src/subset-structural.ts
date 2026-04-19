/**
 * Structural Cedar-policy comparisons for use when the SMT subset prover
 * is unavailable. NEITHER function is a general subset proof.
 *
 * - exactMatch: reflexive only. Sound: a policy is always a subset of itself.
 * - normalizedMatch: strips comments and whitespace, sorts statements, then
 *   checks reflexive equality. Tolerates cosmetic differences but is still
 *   ONLY reflexive. It will not identify cases where the child is a strict
 *   subset of the parent.
 *
 * Both functions are sound in one direction: if they return `true`, the
 * child is guaranteed to be a subset of the parent (by equality). They are
 * incomplete: they will return `false` for many legitimate subset relations
 * that only the SMT prover can establish.
 *
 * The historical `parent.includes(child)` fallback was UNSOUND — it could
 * return `true` when the child string happened to appear inside a comment
 * or inside one of several clauses, even when the child expressed broader
 * permissions. It has been removed.
 */

/** Strictly reflexive byte equality after trimming leading/trailing whitespace. */
export function exactMatch(parent: string, child: string): boolean {
  return parent.trim() === child.trim();
}

/**
 * Normalize a Cedar policy text for structural comparison:
 *   1. Strip line comments (// ...) and block comments (/* ... *\/).
 *   2. Collapse all runs of whitespace to a single space.
 *   3. Split on semicolons into individual statements.
 *   4. Trim each statement, drop empties, sort lexicographically.
 *   5. Rejoin with "; " and a trailing semicolon.
 *
 * Two policies that are textually different but express the same set of
 * statements in a different order or with different whitespace will
 * produce the same normalized form.
 */
export function normalize(policy: string): string {
  // Strip block comments first (before line comments, to avoid cases where
  // a // inside a block comment would confuse us).
  let stripped = policy.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Strip line comments.
  stripped = stripped.replace(/\/\/[^\n]*/g, ' ');
  // Collapse whitespace.
  stripped = stripped.replace(/\s+/g, ' ').trim();
  // Strip whitespace adjacent to Cedar punctuation so that
  //   "permit( principal , action )"
  // and
  //   "permit(principal, action)"
  // normalize the same way. We insert exactly one space after comma to keep
  // the output human-readable.
  stripped = stripped
    .replace(/\s*\(\s*/g, '(')
    .replace(/\s*\)\s*/g, ')')
    .replace(/\s*,\s*/g, ', ')
    .replace(/\s*==\s*/g, ' == ')
    .replace(/\s*;\s*/g, ';');

  // Split on semicolons but preserve them as statement terminators.
  const statements = stripped
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0)
    .sort();

  if (statements.length === 0) return '';
  return statements.join('; ') + ';';
}

/** Reflexive structural match after comment/whitespace/order normalization. */
export function normalizedMatch(parent: string, child: string): boolean {
  return normalize(parent) === normalize(child);
}
