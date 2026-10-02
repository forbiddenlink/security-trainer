import { describe, it, expect } from "vitest";
import type { Module } from "../types";
import {
  estimateLessonMinutes,
  estimateModuleMinutes,
  formatMinutes,
  getLessonMix,
  getModuleStatus,
  getNextLesson,
  getRemainingMinutes,
} from "./moduleMeta";

const words = (n: number) => Array.from({ length: n }, () => "word").join(" ");

const mod: Module = {
  id: "m1",
  title: "Test",
  description: "d",
  difficulty: "Beginner",
  xpReward: 100,
  locked: false,
  lessons: [
    { id: "a", title: "Theory", type: "theory", content: words(400) },
    {
      id: "b",
      title: "Quiz",
      type: "quiz",
      content: "",
      quiz: {
        question: "q",
        options: ["x"],
        correctAnswer: 0,
        explanation: "",
      },
    },
    {
      id: "c",
      title: "Lab",
      type: "lab",
      content: "",
      lab: { initialCode: "", solutionCode: "", instructions: "" },
    } as Module["lessons"][number],
  ],
};

describe("estimateLessonMinutes", () => {
  it("reads theory at 200 words per minute, at least 2 minutes", () => {
    expect(estimateLessonMinutes(mod.lessons[0])).toBe(2);
    expect(
      estimateLessonMinutes({ ...mod.lessons[0], content: words(1000) }),
    ).toBe(5);
  });

  it("gives quizzes 2 minutes and labs 10 minutes", () => {
    expect(estimateLessonMinutes(mod.lessons[1])).toBe(2);
    expect(estimateLessonMinutes(mod.lessons[2])).toBe(10);
  });
});

describe("estimateModuleMinutes", () => {
  it("sums lesson estimates", () => {
    expect(estimateModuleMinutes(mod)).toBe(14);
  });
});

describe("getRemainingMinutes", () => {
  it("skips completed lessons", () => {
    expect(getRemainingMinutes(mod, ["a", "b"])).toBe(10);
  });
});

describe("formatMinutes", () => {
  it("formats minutes and hours", () => {
    expect(formatMinutes(9)).toBe("9 min");
    expect(formatMinutes(60)).toBe("1 hr");
    expect(formatMinutes(95)).toBe("1 hr 35 min");
  });
});

describe("getLessonMix", () => {
  it("counts lesson types", () => {
    expect(getLessonMix(mod)).toEqual({ theory: 1, quiz: 1, lab: 1 });
  });
});

describe("getNextLesson", () => {
  it("returns the first lesson not yet completed", () => {
    expect(getNextLesson(mod, [])?.id).toBe("a");
    expect(getNextLesson(mod, ["a"])?.id).toBe("b");
  });

  it("returns undefined when every lesson is done", () => {
    expect(getNextLesson(mod, ["a", "b", "c"])).toBeUndefined();
  });
});

describe("getModuleStatus", () => {
  it("is done when the module is in completedModules", () => {
    expect(getModuleStatus(mod, ["m1"], [])).toBe("done");
  });

  it("is in-progress when some lessons are complete", () => {
    expect(getModuleStatus(mod, [], ["a"])).toBe("in-progress");
  });

  it("is new otherwise", () => {
    expect(getModuleStatus(mod, [], ["zzz"])).toBe("new");
  });
});
