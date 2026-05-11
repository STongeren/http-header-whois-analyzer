"""
HTTP Header Analyzer
====================
Wat doet dit script?
  - Vraagt hoeveel URLs je wilt testen
  - Haalt voor elke URL de HTTP-headers op
  - Analyseert welke beveiligingsheaders aanwezig of afwezig zijn
  - Geeft een beveiligingsscore (0-100)
  - Slaat alles op in een rapport (header_rapport_DATUM_TIJD.txt)

Waarom beveiligingsheaders?
  Servers sturen headers mee bij elk HTTP-antwoord. Sommige headers zijn
  puur informatief (Server, Content-Type), maar beveiligingsheaders vertellen
  de browser hoe hij zich moet gedragen om aanvallen te voorkomen.
"""

import urllib.request
import urllib.error
import datetime
import ssl

# ── Beveiligingsheaders die we controleren ─────────────────────────────────
# Dit is een woordenboek (dict): key = headernaam, value = uitleg
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS – dwingt HTTPS af, voorkomt protocol-downgrade aanvallen",
    "Content-Security-Policy":   "CSP – beperkt welke bronnen geladen mogen worden (voorkomt XSS)",
    "X-Frame-Options":           "Voorkomt dat de site in een iframe wordt geladen (clickjacking)",
    "X-Content-Type-Options":    "Voorkomt dat de browser MIME-type raadt (nosniff)",
    "Referrer-Policy":           "Bepaalt hoeveel referrer-info meegaat bij links",
    "Permissions-Policy":        "Beheert toegang tot camera, microfoon, locatie, etc.",
    "X-XSS-Protection":         "Verouderde XSS-filter voor oudere browsers (1; mode=block)",
}


def controleer_url(url: str) -> dict:
    """
    Haalt de headers op van één URL en analyseert ze.

    Parameters
    ----------
    url : str
        De URL om te testen (met of zonder https://)

    Returns
    -------
    dict  met sleutels: url, status, headers, aanwezige_headers,
                        ontbrekende_headers, https, fout
    """
    # Zorg dat de URL altijd een schema heeft
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    resultaat = {
        "url":               url,
        "status":            None,
        "headers":           {},
        "aanwezige_headers": {},
        "ontbrekende_headers": [],
        "https":             url.startswith("https://"),
        "fout":              None,
    }

    try:
        # User-Agent meesturen zodat servers ons niet blokkeren als bot
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (SecurityHeaderChecker/1.0)"}
        )
        # urlopen volgt redirects automatisch (301/302)
        response = urllib.request.urlopen(req, timeout=10)

        resultaat["status"]  = response.status
        resultaat["headers"] = dict(response.headers)

    except urllib.error.HTTPError as e:
        # HTTPError wordt gegooid voor 4xx en 5xx statuscodes
        # De headers zijn er nog steeds, dus we bewaren ze
        resultaat["status"]  = e.code
        resultaat["headers"] = dict(e.headers)
        resultaat["fout"]    = f"HTTP {e.code}: {e.reason}"

    except urllib.error.URLError as e:
        # Verbindingsfout (DNS niet gevonden, timeout, etc.)
        resultaat["fout"] = f"Verbindingsfout – {e.reason}"
        return resultaat

    except Exception as e:
        resultaat["fout"] = f"Onverwachte fout – {e}"
        return resultaat

    # ── Beveiligingsheaders analyseren ────────────────────────────────────
    # HTTP headers zijn case-insensitief, dus we zetten alles naar lowercase
    headers_lower = {k.lower(): v for k, v in resultaat["headers"].items()}

    for header, uitleg in SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            resultaat["aanwezige_headers"][header] = headers_lower[header.lower()]
        else:
            resultaat["ontbrekende_headers"].append(header)

    return resultaat


def bereken_score(resultaat: dict) -> int:
    """
    Berekent een beveiligingsscore van 0 tot 100.

    Scoreverdeling
    --------------
    30 punten  →  HTTPS wordt gebruikt
    70 punten  →  verdeeld over de 7 beveiligingsheaders (10 per header)
    """
    if resultaat["fout"] and resultaat["status"] is None:
        return 0

    score = 0

    # +30 voor HTTPS
    if resultaat["https"]:
        score += 30

    # +10 per aanwezige beveiligingsheader
    aanwezig = len(SECURITY_HEADERS) - len(resultaat["ontbrekende_headers"])
    score += aanwezig * 10

    return min(score, 100)


def schrijf_resultaat(resultaat: dict, bestand) -> None:
    """Schrijft het resultaat naar scherm én naar het rapportbestand."""
    score  = bereken_score(resultaat)
    lijn   = "=" * 60

    regels = [
        "",
        lijn,
        f"URL    : {resultaat['url']}",
        f"Status : {resultaat['status'] or 'geen verbinding'}",
        f"HTTPS  : {'Ja ✔' if resultaat['https'] else 'NEE – onveilig!'}",
        f"Score  : {score}/100",
        lijn,
    ]

    if resultaat["fout"]:
        regels.append(f"Fout   : {resultaat['fout']}")
        if not resultaat["headers"]:
            regels.append("(geen headers beschikbaar)")

    if resultaat["headers"]:
        regels.append("")
        regels.append("Alle ontvangen headers:")
        for naam, waarde in sorted(resultaat["headers"].items()):
            regels.append(f"  {naam}: {waarde}")

    regels.append("")
    regels.append("Beveiligingsheaders analyse:")
    for header, uitleg in SECURITY_HEADERS.items():
        if header in resultaat["aanwezige_headers"]:
            waarde = resultaat["aanwezige_headers"][header]
            regels.append(f"  [AANWEZIG]  {header}")
            regels.append(f"              Waarde : {waarde}")
        else:
            regels.append(f"  [ONTBREEKT] {header}")
            regels.append(f"              Waarom : {uitleg}")

    for regel in regels:
        print(regel)
        print(regel, file=bestand)


# ── Hoofdprogramma ──────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  HTTP Header Analyzer")
    print("=" * 60)

    try:
        aantal = int(input("\nHoeveel URLs wil je analyseren? "))
    except ValueError:
        print("Ongeldige invoer – voer een getal in.")
        return

    tijdstempel  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bestandsnaam = f"header_rapport_{tijdstempel}.txt"

    with open(bestandsnaam, "w", encoding="utf-8") as f:
        kop = f"HTTP Header Rapport – gegenereerd op {datetime.datetime.now()}"
        print(kop, file=f)

        for i in range(aantal):
            url = input(f"\nURL {i + 1}: ").strip()
            if not url:
                print("Lege invoer overgeslagen.")
                continue

            print(f"  → Analyseren...")
            resultaat = controleer_url(url)
            schrijf_resultaat(resultaat, f)

    print(f"\nKlaar! Rapport opgeslagen als: {bestandsnaam}")


if __name__ == "__main__":
    main()
