import { describe, it, expect } from "vitest";
import { checkSyntaxHeuristic } from "../syntaxCheck";

describe("checkSyntaxHeuristic", () => {
  it("passes balanced code", () => {
    expect(checkSyntaxHeuristic("function f(a) { return [a, 1]; }")).toBeNull();
  });

  it("ignores brackets inside strings and comments", () => {
    expect(checkSyntaxHeuristic('const s = "){]"; // )]} \n')).toBeNull();
    expect(checkSyntaxHeuristic("/* ){ */ const x = 1;")).toBeNull();
  });

  it("flags an unclosed bracket", () => {
    expect(checkSyntaxHeuristic("function f() {")).toMatch(/Unclosed/);
  });

  it("flags a mismatched closer", () => {
    expect(checkSyntaxHeuristic("const a = [1, 2)")).toMatch(/mismatched/i);
  });

  it("flags an unterminated string", () => {
    expect(checkSyntaxHeuristic('const s = "oops')).toMatch(
      /Unterminated string/,
    );
  });

  it("does not execute code (no eval side effects)", () => {
    // A string that would throw/execute under new Function must be inert here.
    expect(checkSyntaxHeuristic("globalThis.__pwned = true")).toBeNull();
    expect((globalThis as Record<string, unknown>).__pwned).toBeUndefined();
  });
});
