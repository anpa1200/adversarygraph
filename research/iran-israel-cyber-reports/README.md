# Iran-Israel Cyber Report Archive

Downloaded from the report list supplied on 2026-07-01.

## Layout

- `html/` - saved HTML report/news pages.
- `pdf/` - saved PDF reports.
- `pdf-from-html/` - PDFs generated from the saved HTML artifacts with headless Chrome.
- `logs/` - HTTP headers, curl errors, browser fallback logs.
- `download-manifest.tsv` - source URL, local file path, HTTP status, content type, byte count, and result.
- `html-to-pdf-manifest.tsv` - HTML-to-PDF conversion source, output, byte count, and result.

## Download Status

Most links downloaded with HTTP 200 using `curl -L` and a browser user agent.

Browser fallback was used for:

- `fbi-handala-domain-seizure.browser.html` - the FBI URL redirected to the DOJ source page and saved successfully.
- `toi-us-seizure-handala-domains.browser.html` - saved successfully after direct curl returned 403.

Blocked source:

- `reuters-iran-cyberattacks-israel-surged-2026` - Reuters returned HTTP 401 in curl and headless browser. The saved files are only the block response, not the article body.

## HTML-to-PDF Conversion

All 24 saved HTML artifacts were converted to PDF under `pdf-from-html/`.

Important caveats:

- `*.browser.pdf` files were generated from browser-fallback HTML captures.
- `fbi-handala-domain-seizure.browser.pdf` is the useful fallback copy; the direct FBI URL redirected to the DOJ article in the browser.
- `toi-us-seizure-handala-domains.browser.pdf` is the useful fallback copy; the direct curl artifact was a 403 response.
- `reuters-iran-cyberattacks-israel-surged-2026*.pdf` files are block-response PDFs, not the Reuters article body.

## High-Value Technical Sources

- Check Point Handala Hack
- Check Point Iranian MOIS actors and cyber-crime connection
- Unit 42 Handala wiper risk
- Unit 42 Iranian cyber threat evolution
- Unit 42 Screening Serpens
- Check Point Nimbus Manticore reports
- Broadcom/Symantec Seedworm report
- ESET MuddyWater report and press release
- KELA Handala Telegram breach report
- DOJ disruption notice
- INCD 2025 Summary Report PDF

Use `download-manifest.tsv` as the source of truth for ingestion into AdversaryGraph or for later deduplication.
