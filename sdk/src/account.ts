/**
 * AccountId validation and name-hierarchy helpers.
 *
 * The validation rules mirror `chain/crates/primitives/src/account.rs` EXACTLY:
 *   - length in [MIN_LEN, MAX_LEN] *bytes*;
 *   - characters limited to a-z, 0-9, and the separators '-', '_', '.';
 *   - separators may not lead, trail, or be adjacent.
 *
 * The Rust impl measures length in bytes (`id.len()`) and validates per byte,
 * so we measure UTF-8 byte length here too. Since every allowed character is a
 * single ASCII byte, any multi-byte input is rejected as an invalid character
 * before length can disagree — but we use byte length to stay faithful.
 */

/** Minimum identifier length, in bytes. */
export const MIN_LEN = 2;

/** Maximum identifier length, in bytes. */
export const MAX_LEN = 64;

const SEPARATORS = new Set(["-", "_", "."]);

function isSeparator(ch: string): boolean {
  return SEPARATORS.has(ch);
}

function isLowerAlnum(ch: string): boolean {
  return (ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9");
}

/** UTF-8 byte length of a string (matches Rust `str::len`). */
function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** Error thrown when an account id fails validation. */
export class AccountIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountIdError";
  }
}

/**
 * Validate `id` against the protocol rules. Returns `true` if well-formed.
 * Pure predicate — does not throw.
 */
export function isValidAccountId(id: string): boolean {
  try {
    assertValidAccountId(id);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate `id`, throwing {@link AccountIdError} with a specific reason on
 * failure. Mirrors the Rust error ordering: length, then edge separator, then a
 * single forward pass checking characters and adjacency.
 */
export function assertValidAccountId(id: string): void {
  if (typeof id !== "string") {
    throw new AccountIdError("account id must be a string");
  }
  const len = byteLength(id);
  if (len < MIN_LEN || len > MAX_LEN) {
    throw new AccountIdError(
      `account id length ${len} is outside [${MIN_LEN}, ${MAX_LEN}]`,
    );
  }

  // Work over Unicode code points; any non-ASCII char will fail the char check.
  const chars = Array.from(id);
  const first = chars[0]!;
  const last = chars[chars.length - 1]!;
  if (isSeparator(first) || isSeparator(last)) {
    throw new AccountIdError(
      "account id may not start or end with a separator",
    );
  }

  let prevSep = false;
  for (const ch of chars) {
    const ok = isLowerAlnum(ch) || isSeparator(ch);
    if (!ok) {
      throw new AccountIdError(`invalid character ${JSON.stringify(ch)} in account id`);
    }
    if (isSeparator(ch)) {
      if (prevSep) {
        throw new AccountIdError("account id may not contain adjacent separators");
      }
      prevSep = true;
    } else {
      prevSep = false;
    }
  }
}

/**
 * A validated, normalized account identifier. Construction is the only way to
 * obtain one, so any `AccountId` instance is guaranteed well-formed — mirroring
 * the Rust newtype's guarantee.
 */
export class AccountId {
  readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /** Validate and construct. Throws {@link AccountIdError} on failure. */
  static parse(raw: string): AccountId {
    assertValidAccountId(raw);
    return new AccountId(raw);
  }

  /** Validate and construct, returning `null` instead of throwing. */
  static tryParse(raw: string): AccountId | null {
    return isValidAccountId(raw) ? new AccountId(raw) : null;
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }

  /** The dotted hierarchy labels, e.g. "usa.reserve.sov" -> ["usa","reserve","sov"]. */
  labels(): string[] {
    return this.value.split(".");
  }

  /**
   * The top-level label: the segment after the final '.', e.g. "sov" in
   * "usa.reserve.sov". Returns the whole id if there is no '.' separator.
   * Matches Rust `AccountId::top_level`.
   */
  topLevel(): string {
    const idx = this.value.lastIndexOf(".");
    return idx === -1 ? this.value : this.value.slice(idx + 1);
  }

  /**
   * The parent namespace: this id with its first (leftmost) label removed, e.g.
   * "usa.reserve.sov" -> "reserve.sov". Returns `null` for an id with no '.'
   * (a bare label has no parent). The parent is itself a valid AccountId.
   */
  parent(): AccountId | null {
    const idx = this.value.indexOf(".");
    if (idx === -1) return null;
    return AccountId.parse(this.value.slice(idx + 1));
  }

  /**
   * Whether this id is a top-level (registrar-level) name: exactly two dotted
   * labels, e.g. "treasury.sov". "usa.reserve.sov" (3 labels) and "treasury"
   * (1 label) are not top-level.
   */
  isTopLevel(): boolean {
    return this.labels().length === 2;
  }
}

/** Functional helper: top-level label of a raw id string. Throws if invalid. */
export function topLevel(raw: string): string {
  return AccountId.parse(raw).topLevel();
}

/** Functional helper: parent of a raw id string, or null. Throws if invalid. */
export function parentOf(raw: string): string | null {
  const p = AccountId.parse(raw).parent();
  return p === null ? null : p.value;
}

/** Functional helper: whether a raw id string is top-level. Throws if invalid. */
export function isTopLevel(raw: string): boolean {
  return AccountId.parse(raw).isTopLevel();
}
