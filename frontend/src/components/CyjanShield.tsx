export function CyjanShield() {
  return (
    <svg viewBox="0 0 280 320" xmlns="http://www.w3.org/2000/svg" className="cyjan-shield-svg">
      <defs>
        <radialGradient id="shieldGlow" cx="50%" cy="55%" r="55%">
          <stop offset="0%"   stopColor="#22d3ee" stopOpacity="0.22" />
          <stop offset="60%"  stopColor="#06b6d4" stopOpacity="0.06" />
          <stop offset="100%" stopColor="#061a2e" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="shieldStroke" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor="#67e8f9" />
          <stop offset="100%" stopColor="#0891b2" />
        </linearGradient>
      </defs>

      <path d="M140 14 L252 64 L252 186 Q252 270 140 312 Q28 270 28 186 L28 64 Z"
            fill="url(#shieldGlow)" stroke="#06b6d4" strokeWidth="1.5" opacity="0.55" />

      <path d="M140 24 L244 70 L244 184 Q244 258 140 300 Q36 258 36 184 L36 70 Z"
            fill="#061a2e" stroke="url(#shieldStroke)" strokeWidth="2.2" />

      <path d="M140 36 L234 78 L234 182 Q234 248 140 288 Q46 248 46 182 L46 78 Z"
            fill="none" stroke="#22d3ee" strokeWidth="1" opacity="0.45" />

      <g stroke="#22d3ee" strokeWidth="0.9" fill="none" opacity="0.28">
        <polygon points="120,122 140,110 160,122 160,146 140,158 120,146" />
        <polygon points="100,158 120,146 140,158 140,182 120,194 100,182" />
        <polygon points="140,158 160,146 180,158 180,182 160,194 140,182" />
        <polygon points="120,194 140,182 160,194 160,218 140,230 120,218" />
      </g>
      <polygon points="140,158 160,146 180,158 180,182 160,194 140,182"
               fill="#06b6d4" opacity="0.25" />

      <ellipse cx="140" cy="176" rx="44" ry="24" fill="none" stroke="#22d3ee" strokeWidth="1.8" opacity="0.9" />
      <circle  cx="140" cy="176" r="16" fill="none" stroke="#22d3ee" strokeWidth="1.4" opacity="0.85" />
      <circle  cx="140" cy="176" r="9"  fill="none" stroke="#67e8f9" strokeWidth="1.1" opacity="0.7" />
      <circle  cx="140" cy="176" r="4"  fill="#22d3ee" />
      <circle  cx="140" cy="176" r="1.8" fill="#e0f9ff" />

      <g stroke="#22d3ee" strokeWidth="1.2" opacity="0.65">
        <line x1="70"  y1="176" x2="92"  y2="176" />
        <line x1="188" y1="176" x2="210" y2="176" />
      </g>
    </svg>
  );
}
