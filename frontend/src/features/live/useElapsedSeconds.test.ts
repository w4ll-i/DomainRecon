import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useElapsedSeconds } from "./useElapsedSeconds";

// Seules la minuterie et l'horloge sont simulées : les attentes de Testing Library et
// de TanStack Query gardent leurs vraies minuteries.
function fakeClock() {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
}

describe("chronomètre du suivi en direct", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("compte les secondes tant que la tâche tourne, puis garde la valeur quand elle s'arrête", () => {
    fakeClock();
    const { result, rerender } = renderHook(({ active }) => useElapsedSeconds(active), { initialProps: { active: true } });
    expect(result.current).toBe(0);
    act(() => {
      vi.advanceTimersByTime(7000);
    });
    expect(result.current).toBe(7);
    rerender({ active: false });
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(result.current).toBe(7);
  });

  it("ne démarre pas quand la tâche n'est pas active", () => {
    fakeClock();
    const { result } = renderHook(() => useElapsedSeconds(false));
    act(() => {
      vi.advanceTimersByTime(4000);
    });
    expect(result.current).toBe(0);
  });

  it("libère sa minuterie au démontage", () => {
    fakeClock();
    const { unmount } = renderHook(() => useElapsedSeconds(true));
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
