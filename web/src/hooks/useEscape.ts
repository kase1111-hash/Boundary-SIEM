import { useEffect, useRef } from "react";

/**
 * Calls onEscape when Escape is pressed while active, so a modal can be
 * dismissed from the keyboard. (The rule dialogs could only be closed with
 * the mouse, and blocked the navigation until then.)
 */
export function useEscape(onEscape: () => void, active = true): void {
  // Keep the latest callback without re-subscribing when it changes identity
  const callback = useRef(onEscape);
  callback.current = onEscape;

  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") callback.current();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [active]);
}
