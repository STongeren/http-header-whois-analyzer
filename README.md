# HTTP header and WHOIS analyzer

Two small Python recon tools from my Cyber Security programme at the Hogeschool van Amsterdam (week 2: headers and WHOIS).

| Script | What it does |
|---|---|
| `header_analyzer.py` | Fetches the HTTP response headers of one or more URLs, checks which security headers are present (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), gives a 0-100 score and writes a report |
| `whois_analyzer.py` | Looks up the WHOIS record of a domain and reports registrar, creation date, expiry date and how many days are left before it expires |

## Why it matters

Missing security headers are one of the most common findings in a web pentest, and a newly registered or nearly expired domain is a useful signal when you triage a phishing link.

## Run

```
pip install python-whois
python header_analyzer.py
python whois_analyzer.py
```

Only `whois_analyzer.py` needs an extra package; `header_analyzer.py` uses the standard library. Output and comments are in Dutch.
