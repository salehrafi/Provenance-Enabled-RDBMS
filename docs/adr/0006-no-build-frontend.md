# ADR 0006: Dependency-free ES-module frontend served by the API

Status: accepted · Date: 2026-11-13

## Context
The UI must be easy to run (clone, then run), safe under a strict CSP, and cheap to keep secure (no front-end supply chain).

## Decision
Vanilla ES modules, no framework, no build step, no third-party scripts. DOM is built with a small `h()` helper that only creates text nodes and never uses `innerHTML`. The visual design is the original flat, square-cornered green theme (Poppins, bordered grey sidebar); it is expressed as CSS custom properties, light by default, with an opt-in dark theme (toggle in the sidebar, remembered in `localStorage`). Below 821 px the sidebar becomes a slide-in drawer opened from a top bar.

## Consequences
* `script-src 'self'`, no inline script, no `eval`; no npm tree to audit. (Inline `style` attributes are used, so `style-src` allows `'unsafe-inline'`. Poppins is loaded from Google Fonts, as in the original UI, so `style-src`/`font-src` also allow `fonts.googleapis.com` / `fonts.gstatic.com`; browsers therefore send the visitor's IP to Google. Self-host the font files and remove those two origins from `CSP` in `app/main.py` if that is unacceptable. The UI falls back to the system font if the font cannot load.)
* Less ergonomic than a framework for a much larger UI and no type-checking of the front end. If the UI grows substantially, adopt TypeScript with a build step and keep the same CSP.
* No automated browser tests yet (TESTING.md).
