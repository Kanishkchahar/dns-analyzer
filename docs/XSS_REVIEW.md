# Dashboard XSS review

Reviewed `static/app.js` after the scan and dashboard changes. There are 76 `innerHTML` assignments (77 textual `innerHTML` occurrences including reads); the count is not itself a vulnerability.

## Review notes

- Dynamic DNS, CT, TLS, mail, remediation, and network-scan text inserted into HTML templates is passed through `escapeHtml` before interpolation.
- Template class names and labels are generated from local fixed maps, boolean branches, counters, or enumerated result states. User and remote text does not select arbitrary element names, event handlers, or style declarations.
- The finding renderer escapes message text before applying only the local backtick-to-`code` formatting rule.
- The newer multi-domain dashboard and extension-check cards use DOM creation plus `textContent`, so domain names, RDAP data, RPKI values, and service evidence are not parsed as HTML.
- The DMARC percentage is converted to a number before interpolation. Domain and subdomain attributes are HTML-escaped before insertion.

No unescaped remote-controlled HTML interpolation was found in this review. This is a source review, not a browser-based security test. Preserve the rule that new response values use `textContent` or `escapeHtml` before entering a template. Never add server-provided markup, `on*` attributes, or URLs to HTML strings.
