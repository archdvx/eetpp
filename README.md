# Implementace EET v c++
Podporuje **EET 2.0** spuštěné od 1.1.2027

Knihovna je inspirována implementací EET [v Javě](https://github.com/l-ra/openeet-java) a je licencován pod GNU LESSER GENERAL PUBLIC Version 3.

Libeetpp používá knihovny [OpenSSL](https://www.openssl.org/) a [libcurl](https://curl.haxx.se/libcurl/).

## Dokumentace
Dokumentace k projektu je dostupná [tady](https://dxsolutions.org/eetpp).

## Kompilace knihovny

```
cd eetpp
mdkir build
cd build
cmake ..
sudo make install
```
_Vyžaduje kompiler s podporou ISO C++ 2017 standardu_

## Příklad

eettest.cpp
```cpp
#include "eet.h"
#include <iostream>

int main(int argc, char **argv)
{
    Eet eet("CZ00000019", 21, "./CA_EET-Playground-CZ00000019.p12", "aaaa1111", "Pokladna 1");
    eet.setPlayground(true);
    EETCODE ret = eet.sendTrzba(EetData("1234/2026", 1113.0));
    if(ret == EET_OK || ret == EET_VAROVANI)
    {
        std::cout << "POK: " << eet.getPok() << std::endl;
        if(ret == EET_VAROVANI)
        {
            std::cout << "Varovani: " << std::endl;
            std::cerr << eet.getVarovani() << std::endl;
        }
    }
    else
    {
        std::cout << "Chyba: " << std::endl;
        std::cerr << eet.getChyba() << std::endl;
    }
    return 0;
}
```

### Kompilace

```
c++ -o eettest eettest.cpp $(pkg-config --cflags --libs libeetpp)
```

_Knihovna přilinkována (bez pkg-config: `c++ -o eettest eettest.cpp -I/usr/local/include/eetpp -leetpp -lssl -lcrypto -lcurl`, -leetpp musí být před knihovnami, na kterých závisí)_

```
c++ -o eettest eettest.cpp eet.cpp -lssl -lcrypto -lcurl
```

_Soubory knihovny nakopírovány do projektu_

## Převod certifikátu pro OpenSSL 3

Starší certifikáty PKCS#12 (RC2-40 / 3DES, SHA-1 MAC) OpenSSL 3 bez legacy provideru nenačte.
Skripty ve složce `scripts` je převedou na AES-256-CBC + SHA-256 MAC, heslo zůstává stejné.

```
scripts/p12-convert.sh vstup.p12 [vystup.p12]
```

_Na Windows `scripts\p12-convert.bat`. Heslo se zadá interaktivně, nebo přes proměnnou prostředí P12PASS._

## Plány

* zapracovat případné požadavky uživatelů
* sledovat změny v požadavcích EET a implementovat je
