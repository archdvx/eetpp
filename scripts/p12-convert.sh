#!/usr/bin/env bash
# Převede PKCS#12 certifikát se starým šifrováním (RC2-40 / 3DES, SHA-1 MAC)
# na AES-256-CBC + SHA-256 MAC, který OpenSSL 3 načte bez legacy provideru.
# Heslo zůstává stejné. Privátní klíč se na disk dostane jen zašifrovaný.
#
# Použití: ./p12-convert.sh vstup.p12 [vystup.p12]
#          heslo se zadá interaktivně, nebo přes proměnnou prostředí P12PASS

set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Použití: $0 vstup.p12 [vystup.p12]" >&2
    exit 1
fi

in=$1
out=${2:-${in%.p12}-aes.p12}

if [ ! -f "$in" ]; then
    echo "Soubor $in neexistuje" >&2
    exit 1
fi
if [ -e "$out" ]; then
    echo "Výstupní soubor $out už existuje, nepřepisuji ho" >&2
    exit 1
fi

if [ -z "${P12PASS:-}" ]; then
    read -rsp "Heslo k certifikátu: " P12PASS
    echo
fi
export P12PASS

# Volba -legacy existuje až v OpenSSL 3; starší verze RC2 umí bez ní
legacy=
if openssl version | grep -q '^OpenSSL 3'; then
    legacy=-legacy
fi

# openssl pkcs12 -export čte vstup dvakrát (klíč a certifikáty), takže nejde použít
# roura - mezivýsledek jde do dočasného PEM s klíčem zašifrovaným AES-256 stejným heslem
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

if ! openssl pkcs12 $legacy -in "$in" -passin env:P12PASS -out "$tmp" -aes256 -passout env:P12PASS \
    || ! openssl pkcs12 -export -in "$tmp" -passin env:P12PASS -out "$out" -passout env:P12PASS \
        -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256; then
    echo "Převod selhal (chybné heslo nebo poškozený soubor)" >&2
    rm -f "$out"
    exit 1
fi

# Kontrola: nový soubor musí jít otevřít bez legacy provideru
if ! openssl pkcs12 -in "$out" -noout -passin env:P12PASS 2>/dev/null; then
    echo "Převedený soubor nejde otevřít, mažu ho" >&2
    rm -f "$out"
    exit 1
fi

echo "Hotovo: $out"
