# Aegis website

A self-contained, dependency-free static landing page (dark tech theme).

## Local preview
Open `index.html` in a browser, or serve the folder:
```bash
npx serve site      # or: python -m http.server -d site 8080
```

## Deploy (static)
Point any static host at this `site/` directory. For Vercel, set the project's
**Root Directory** to `site` (no build command needed) — or from the repo root:
```bash
vercel deploy site --prod
```

Files: `index.html`, `styles.css`, `assets/` (logo + cover). No framework, no build step.
