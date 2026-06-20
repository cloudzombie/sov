import { describe, expect, it } from "vitest";
import {
  AccountId,
  AccountIdError,
  MAX_LEN,
  assertValidAccountId,
  isTopLevel,
  isValidAccountId,
  parentOf,
  topLevel,
} from "../src/account.js";

// These cases mirror chain/crates/primitives/src/account.rs tests exactly.
describe("validation — accepts well-formed ids", () => {
  it.each(["usa.reserve.sov", "val01.node.sov", "treasury.sov", "ab", "a-b_c"])(
    "%s is valid",
    (id) => {
      expect(isValidAccountId(id)).toBe(true);
      expect(() => assertValidAccountId(id)).not.toThrow();
    },
  );
});

describe("validation — rejects malformed ids (matching Rust error reasons)", () => {
  it("length too short", () => {
    expect(isValidAccountId("a")).toBe(false);
    expect(() => assertValidAccountId("a")).toThrow(/length 1 is outside/);
  });
  it("leading/trailing separator", () => {
    expect(() => assertValidAccountId(".sov")).toThrow(/start or end with a separator/);
    expect(() => assertValidAccountId("sov.")).toThrow(/start or end with a separator/);
    expect(() => assertValidAccountId("-ab")).toThrow(/start or end/);
    expect(() => assertValidAccountId("ab_")).toThrow(/start or end/);
  });
  it("adjacent separators", () => {
    expect(() => assertValidAccountId("a..b")).toThrow(/adjacent separators/);
    expect(() => assertValidAccountId("a-_b")).toThrow(/adjacent separators/);
  });
  it("invalid characters", () => {
    expect(() => assertValidAccountId("USA.sov")).toThrow(/invalid character/);
    expect(() => assertValidAccountId("a b")).toThrow(/invalid character/);
    expect(() => assertValidAccountId("a@b")).toThrow(/invalid character/);
  });
  it("length too long (> 64 bytes)", () => {
    const tooLong = "a".repeat(MAX_LEN + 1);
    expect(isValidAccountId(tooLong)).toBe(false);
    expect(isValidAccountId("a".repeat(MAX_LEN))).toBe(true);
  });
  it("non-ascii is rejected as an invalid character", () => {
    expect(isValidAccountId("café.sov")).toBe(false);
  });
});

describe("AccountId construction", () => {
  it("parse throws on invalid", () => {
    expect(() => AccountId.parse("BAD")).toThrow(AccountIdError);
  });
  it("tryParse returns null on invalid, instance on valid", () => {
    expect(AccountId.tryParse("BAD")).toBeNull();
    expect(AccountId.tryParse("treasury.sov")?.value).toBe("treasury.sov");
  });
  it("toString / toJSON yield the raw value", () => {
    const id = AccountId.parse("usa.reserve.sov");
    expect(id.toString()).toBe("usa.reserve.sov");
    expect(JSON.stringify({ a: id })).toBe('{"a":"usa.reserve.sov"}');
  });
});

describe("hierarchy helpers", () => {
  it("topLevel matches Rust top_level", () => {
    expect(AccountId.parse("usa.reserve.sov").topLevel()).toBe("sov");
    // No dot -> whole id (Rust returns the whole string).
    expect(AccountId.parse("treasury").topLevel()).toBe("treasury");
    expect(topLevel("ecb.reserve.sov")).toBe("sov");
  });

  it("parent removes the leftmost label", () => {
    expect(AccountId.parse("usa.reserve.sov").parent()?.value).toBe("reserve.sov");
    expect(AccountId.parse("reserve.sov").parent()?.value).toBe("sov" + "");
    // "sov" alone is only 3 chars but valid; a bare label has no parent.
    expect(AccountId.parse("treasury").parent()).toBeNull();
    expect(parentOf("usa.reserve.sov")).toBe("reserve.sov");
    expect(parentOf("treasury")).toBeNull();
  });

  it("parent of reserve.sov is the top-level label sov", () => {
    // Note: "sov" is a valid id (3 bytes, in range), so parent returns it.
    expect(parentOf("reserve.sov")).toBe("sov");
  });

  it("isTopLevel is true for exactly two dotted labels", () => {
    expect(isTopLevel("treasury.sov")).toBe(true);
    expect(AccountId.parse("treasury.sov").isTopLevel()).toBe(true);
    expect(isTopLevel("usa.reserve.sov")).toBe(false);
    expect(isTopLevel("treasury")).toBe(false);
  });

  it("labels splits on dots", () => {
    expect(AccountId.parse("usa.reserve.sov").labels()).toEqual(["usa", "reserve", "sov"]);
  });
});
