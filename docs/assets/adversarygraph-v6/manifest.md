# AdversaryGraph v6 Screenshot Evidence

Captured on 2026-07-17 from the production-built frontend preview at
`1920x1200` with Chromium and sanitized deterministic API fixtures. The source
revision is `v6.0.0` commit
`987623854d9e577cee02f1c12772f610b89785b8`.

The images demonstrate the UI and documented controls at the immutable
`v6.0.0` tag. They are not evidence for later changes on `main` and do not prove
a live external feed, successful exploit, customer deployment, or real-world
detection. Fixture values use fictional records and approved lab targets; no
credentials, private reports, customer data, or malware are included.

## Reproduce

```bash
git checkout v6.0.0
cd frontend
npm ci
npx playwright install chromium
npm run build
npm run screenshots:v6
```

The capture test asserts expected page content before writing each image and
closes transient self-test UI so the documented workflow remains visible.

## Captures

| File | Surface | Evidence shown |
|---|---|---|
| `01-discover-workspace.png` | Discover | v6.0.0 module navigation and workflow launchers spanning intelligence, asset, simulation, evidence, and malware analysis |
| `02-attack-simulation-matrix.png` | Attack Simulation | ATT&CK technique selection and explicit indication that a runnable approved scenario exists |
| `03-attack-assistant-evidence.png` | Attack Simulation detail | Approved target context, real-time log area, guarded SIEM forwarding, AI assistant boundary, and saved attack-flow evidence |
| `04-cve-library.png` | CVE Library | Search, severity/KEV filters, CVSS display, source controls, and strict evidence-link guidance |

## Validation Metadata

All images are non-empty 8-bit RGB PNG files at 1920x1200. Checksums are
recorded in [`sha256sums.txt`](sha256sums.txt) and can be verified with:

```bash
cd docs/assets/adversarygraph-v6
sha256sum -c sha256sums.txt
```
