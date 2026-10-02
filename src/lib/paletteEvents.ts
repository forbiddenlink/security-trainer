export const OPEN_PALETTE_EVENT = "sectrainer:open-palette";

/** Open the command palette from anywhere (header button, empty states). */
export function openCommandPalette(): void {
  window.dispatchEvent(new Event(OPEN_PALETTE_EVENT));
}
