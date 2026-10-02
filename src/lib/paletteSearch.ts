export type PaletteKind = "page" | "module" | "path" | "ctf";

export interface PaletteItem {
  id: string;
  kind: PaletteKind;
  title: string;
  href: string;
  subtitle?: string;
  keywords?: string;
}

/**
 * Filter and rank palette items. Every query word must appear in the title,
 * subtitle or keywords. Title prefix matches rank first, then title
 * substring matches, then keyword-only matches; ties keep input order.
 */
export function rankPaletteItems(
  items: readonly PaletteItem[],
  query: string,
): PaletteItem[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [...items];

  const scored: { item: PaletteItem; score: number; index: number }[] = [];
  items.forEach((item, index) => {
    const title = item.title.toLowerCase();
    const haystack =
      `${title} ${item.subtitle ?? ""} ${item.keywords ?? ""}`.toLowerCase();
    if (!words.every((w) => haystack.includes(w))) return;
    const first = words[0];
    const score = title.startsWith(first) ? 0 : title.includes(first) ? 1 : 2;
    scored.push({ item, score, index });
  });

  return scored
    .sort((a, b) => a.score - b.score || a.index - b.index)
    .map((s) => s.item);
}
