// ISO-3166-1-alpha-2 → Unicode-Flag-Glyph + Tooltip-Helfer.
//
// Eine Flagge im Unicode ist ein Pärchen aus zwei "Regional Indicator Symbol
// Letters" (Codepunkte 0x1F1E6 + Letter-'A'). Der Browser/OS-Font rendert
// das Pärchen automatisch als Landesflagge — keine Bilder, keine Lib.
// Auf Linux-Servern ohne Color-Emoji-Font (z.B. CI-Snapshots) zeigen die
// Glyphen stattdessen "DE", "US", … — bleibt also informativ.

export function countryFlag(code: string | undefined | null): string {
  if (!code || code.length !== 2) return '';
  const A = 0x1F1E6;
  const upper = code.toUpperCase();
  return String.fromCodePoint(
    A + upper.charCodeAt(0) - 65,
    A + upper.charCodeAt(1) - 65,
  );
}

// Tooltip-Text für eine geo-Aussage: "Land — Stadt" wenn beides da, sonst
// der Code als Fallback.
export function geoTooltip(geo?: { country?: string; city?: string; country_code?: string } | null): string {
  if (!geo) return '';
  const parts = [geo.country, geo.city].filter(Boolean);
  if (parts.length) return parts.join(' — ');
  return geo.country_code ?? '';
}
