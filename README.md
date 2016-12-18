# Implementace EET v c++
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
_Vyžaduje kompiler s podporou ISO C++ 2011 standardu_

## Příklad

eettest.cpp
```cpp
#include "eet.h"
#include <iostream>

int main(int argc, char **argv)
{
    Eet eet("CZ1212121218", 21, "./EET_CA1_Playground-CZ1212121218.p12", "eet", "Pokladna 1");
    eet.setPlayground(true);
    EETCODE ret = eet.sendTrzba(EetData("1234/2016", 1113.0));
    if(ret == EET_OK || ret == EET_VAROVANI)
    {
        std::cout << "PKP: "<< eet.getPkp() << std::endl;
        std::cout << "BKP: "<< eet.getBkp() << std::endl;
        std::cout << "FIK: "<< eet.getFik() << std::endl;
        if(ret == EET_VAROVANI) std::cerr << eet.getVarovani() << std::endl;
    }
    else
    {
        std::cerr << eet.getChyba() << std::endl;
    }
    return 0;
}
```

### Kompilace

```
c++ -o eettest eettest.cpp eet.cpp -lssl -lcrypto -lcurl -leetpp
```

_Knihovna přilinkována_

```
c++ -o eettest eettest.cpp eet.cpp -lssl -lcrypto -lcurl
```

_Soubory knihovny nakopírovány do projektu_

## Plány

* zapracovat případné požadavky uživatelů
* sledovat změny v požadavcích EET a implementovat je
