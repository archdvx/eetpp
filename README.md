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
c++ -o eettest eettest.cpp -lssl -lcrypto -lcurl -leetpp
```

_Knihovna přilinkována_

```
c++ -o eettest eettest.cpp eet.cpp -lssl -lcrypto -lcurl
```

_Soubory knihovny nakopírovány do projektu_

## Plány

* zapracovat případné požadavky uživatelů
* sledovat změny v požadavcích EET a implementovat je
