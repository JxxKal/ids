# Installing into `JxxKal/ids` as `design-system/`

Drop this entire folder into the `ids` monorepo at the path `design-system/` so both the dashboard and any future marketing code can import from it.

## 1. Clone and branch

```bash
git clone git@github.com:JxxKal/ids.git
cd ids
git checkout -b feat/design-system
mkdir -p design-system
```

## 2. Copy the folder in

Unzip the download you got from this project and copy its contents into `design-system/`:

```
ids/
├── backend/
├── frontend/
├── design-system/        ← everything from the ZIP lands here
│   ├── README.md
│   ├── SKILL.md
│   ├── colors_and_type.css
│   ├── assets/logos/*.svg
│   ├── preview/*.html
│   └── ui_kits/
│       ├── website/
│       └── dashboard/
├── docker-compose.yml
└── ...
```

## 3. Wire it up in the dashboard (`frontend/`)

### a) Tokens into Tailwind

Open `frontend/tailwind.config.ts` and import the token CSS variables, or copy the palette from `design-system/colors_and_type.css` into the `theme.extend.colors` block. The `--cy-*` custom properties are already valid CSS — the fastest path is to import the file once at the top of your global stylesheet:

```ts
// frontend/src/index.css (or wherever Tailwind's @tailwind base; lives)
@import '../../design-system/colors_and_type.css';
```

Then in `tailwind.config.ts` reference the custom properties:

```ts
theme: {
  extend: {
    colors: {
      cyan: {
        500: 'var(--cy-cyan-500)',
        600: 'var(--cy-cyan-600)',
        // ...
      },
      slate: {
        900: 'var(--cy-slate-900)',
        // ...
      },
      severity: {
        critical: 'var(--cy-sev-critical)',
        high:     'var(--cy-sev-high)',
        medium:   'var(--cy-sev-medium)',
        low:      'var(--cy-sev-low)',
        info:     'var(--cy-sev-info)',
      },
    },
  },
}
```

### b) Logos

```bash
cp design-system/assets/logos/*.svg frontend/public/logos/
```

Reference them as `/logos/cyjan_logo_cyan.svg` from any React component.

### c) Fonts

The design uses **Inter** for marketing surfaces and **JetBrains Mono** for product surfaces. Keep the Google Fonts `<link>` in `frontend/index.html` — it's already identical to what the design system expects.

## 4. Reference UI-kit components

`design-system/ui_kits/website/WebsiteComponents.jsx` and `ui_kits/dashboard/DashboardComponents.jsx` are written as **browser-native JSX** (Babel standalone) so they stay openable standalone. To port them into the real Vite/TS app:

1. Copy the component function you need into a new `.tsx` file under `frontend/src/components/`.
2. Add types — most props are simple strings / numbers.
3. Remove the `Object.assign(window, {...})` line at the bottom (only needed for the standalone preview).
4. Swap CDN `lucide` SVG inlines for `lucide-react` imports if you already have that package.

The components are intentionally self-contained (no cross-file imports) so one-by-one porting is low-risk.

## 5. Marketing site (`cyjan-ids-website` repo — separate)

Same folder can be symlinked or git-submoduled into the marketing repo:

```bash
# in cyjan-ids-website/
git submodule add git@github.com:JxxKal/ids.git vendor/ids
ln -s vendor/ids/design-system design-system
```

Or simpler for a single-file `index.html`: copy `design-system/colors_and_type.css` and the logo SVGs into the marketing repo and inline the token block in `<head>`.

## 6. Commit

```bash
git add design-system/
git commit -m "feat(design-system): add CYJAN IDS design system

- tokens (colors, type, radii, shadows, spacing)
- 5 logo SVGs
- preview cards
- website + dashboard UI kits
- SKILL.md for agent-driven generation"
git push -u origin feat/design-system
```

Open a PR against `main`, request review, merge. Done.

---

## Keeping it alive

- Treat `colors_and_type.css` as the single source of truth. If you need a new token, add it there first and document it in `README.md`.
- New components: prototype them inside `ui_kits/` as standalone JSX, get design sign-off using the preview, **then** port to `frontend/src/components/` as TSX.
- `SKILL.md` makes this folder invocable by an AI agent — keep it updated if the non-negotiable brand rules change.
