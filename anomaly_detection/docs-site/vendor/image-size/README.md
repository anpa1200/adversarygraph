# Documentation image-size boundary

This local package replaces Docusaurus's transitive `image-size` dependency for
the AdversaryGraph Anomaly Detection documentation build.

The documentation repository contains only reviewed SVG assets. The general
ICNS, JXL, and HEIF parsers in upstream `image-size <=2.0.2` are affected by
`GHSA-w3rx-r6r6-pgpr` and `GHSA-5p2g-fcmc-qvqq`, with no patched npm release as
of 2026-08-12. This package therefore implements only bounded SVG dimension
reading and rejects every other format. Do not broaden it without a security
review and dedicated malformed-input tests.

The interface is limited to the `image-size` and `image-size/fromFile` exports
used by Docusaurus. License: MIT.
