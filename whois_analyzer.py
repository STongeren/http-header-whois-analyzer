import whois
import datetime
import socket


def normaliseer_datum(datum) -> datetime.datetime | None:
    if isinstance(datum, list):
        datum = datum[0]
    if not isinstance(datum, datetime.datetime):
        return None
    if datum.tzinfo is not None:
        datum = datum.replace(tzinfo=None)
    return datum


def bereken_verval_status(dagen: int | None) -> str:
    if dagen is None:
        return "Onbekend"
    if dagen < 0:
        return "VERLOPEN! Domein is niet meer actief."
    if dagen < 30:
        return f"KRITIEK – verloopt over {dagen} dagen!"
    if dagen < 90:
        return f"WAARSCHUWING – verloopt over {dagen} dagen."
    return f"OK – verloopt over {dagen} dagen."


def haal_ip_op(domein: str) -> str:
    try:
        return socket.gethostbyname(domein)
    except socket.gaierror:
        return "DNS-fout (domein niet gevonden)"
    except Exception as e:
        return f"Fout: {e}"


def haal_whois_op(domein: str) -> dict:
    resultaat = {
        "domein":             domein,
        "registrar":          None,
        "registrant_land":    None,
        "aangemaakt":         None,
        "bijgewerkt":         None,
        "verloopt":           None,
        "nameservers":        None,
        "status":             None,
        "dnssec":             None,
        "dagen_tot_verlopen": None,
        "verval_status":      None,
        "fout":               None,
    }

    try:
        w = whois.whois(domein)

        resultaat["registrar"]       = w.registrar
        resultaat["registrant_land"] = w.country or w.registrant_country
        resultaat["nameservers"]     = w.name_servers
        resultaat["status"]          = w.status
        resultaat["dnssec"]          = w.dnssec
        resultaat["aangemaakt"]      = normaliseer_datum(w.creation_date)
        resultaat["bijgewerkt"]      = normaliseer_datum(w.updated_date)
        resultaat["verloopt"]        = normaliseer_datum(w.expiration_date)

        if resultaat["verloopt"]:
            dagen = (resultaat["verloopt"] - datetime.datetime.now()).days
            resultaat["dagen_tot_verlopen"] = dagen
            resultaat["verval_status"]      = bereken_verval_status(dagen)
        else:
            resultaat["verval_status"] = bereken_verval_status(None)

    except Exception as e:
        resultaat["fout"] = str(e)

    return resultaat


def formatteer_waarde(waarde) -> str:
    if waarde is None:
        return "Niet beschikbaar"
    if isinstance(waarde, list):
        return ", ".join(str(v) for v in waarde)
    return str(waarde)


def schrijf_resultaat(domein: str, ip: str, whois_data: dict, bestand) -> None:
    lijn = "=" * 60

    regels = [
        "",
        lijn,
        f"Domein          : {domein}",
        f"IP-adres        : {ip}",
        lijn,
    ]

    if whois_data["fout"]:
        regels.append(f"FOUT bij WHOIS  : {whois_data['fout']}")
    else:
        regels += [
            f"Registrar       : {formatteer_waarde(whois_data['registrar'])}",
            f"Registrant land : {formatteer_waarde(whois_data['registrant_land'])}",
            f"Aangemaakt      : {formatteer_waarde(whois_data['aangemaakt'])}",
            f"Bijgewerkt      : {formatteer_waarde(whois_data['bijgewerkt'])}",
            f"Verloopt        : {formatteer_waarde(whois_data['verloopt'])}",
            f"Nameservers     : {formatteer_waarde(whois_data['nameservers'])}",
            f"Status          : {formatteer_waarde(whois_data['status'])}",
            f"DNSSEC          : {formatteer_waarde(whois_data['dnssec'])}",
            "",
            f">>> {whois_data['verval_status']}",
        ]

    for regel in regels:
        print(regel)
        print(regel, file=bestand)


def main():
    print("=" * 60)
    print("  WHOIS Analyzer")
    print("=" * 60)

    try:
        aantal = int(input("\nHoeveel domeinen wil je onderzoeken? "))
    except ValueError:
        print("Ongeldige invoer – voer een getal in.")
        return

    tijdstempel  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bestandsnaam = f"whois_rapport_{tijdstempel}.txt"

    with open(bestandsnaam, "w", encoding="utf-8") as f:
        print(f"WHOIS Rapport – gegenereerd op {datetime.datetime.now()}", file=f)

        for i in range(aantal):
            domein = input(f"\nDomein {i + 1} (bijv. example.com): ").strip()
            if not domein:
                print("Lege invoer overgeslagen.")
                continue

            domein = domein.replace("https://", "").replace("http://", "").split("/")[0]

            print("  → IP opzoeken...")
            ip = haal_ip_op(domein)

            print("  → WHOIS opzoeken...")
            whois_data = haal_whois_op(domein)

            schrijf_resultaat(domein, ip, whois_data, f)

    print(f"\nKlaar! Rapport opgeslagen als: {bestandsnaam}")


if __name__ == "__main__":
    main()
