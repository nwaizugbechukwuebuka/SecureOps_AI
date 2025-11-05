SecureOps AI — GitHub Pages static demo

This folder contains a minimal static preview of the SecureOps AI frontend suitable for hosting on GitHub Pages.

Files:
- index.html — static SPA entry
- style.css — site styles
- script.js — small client-side router + mocked data

How to publish on GitHub Pages:
1. Commit and push the `docs/` folder to your repository's default branch.
2. In GitHub repository Settings -> Pages, choose the source: "Deploy from a branch" and set the folder to `/docs` on the default branch.
3. Save and wait a minute for the site to build.

Notes:
- This demo is intentionally read-only and does not contact the backend. To convert the full React app you'll need to either build the app to static assets or replace runtime API calls with fetches against hosted APIs.
- For a richer export, consider running `npm run build` and copying the contents of `dist/` into `docs/` after adjusting environment variables to point to mocked APIs if necessary.
