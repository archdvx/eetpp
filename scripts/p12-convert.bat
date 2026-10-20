@echo off
rem Prevede PKCS#12 certifikat se starym sifrovanim (RC2-40 / 3DES, SHA-1 MAC)
rem na AES-256-CBC + SHA-256 MAC, ktery OpenSSL 3 nacte bez legacy provideru.
rem Heslo zustava stejne. Privatni klic se na disk dostane jen zasifrovany.
rem Vyzaduje openssl.exe (verze 3) v PATH, napr. z MSYS2 (ucrt64\bin).
rem
rem Pouziti: p12-convert.bat vstup.p12 [vystup.p12]

setlocal
if "%~1"=="" (
    echo Pouziti: %~nx0 vstup.p12 [vystup.p12]
    exit /b 1
)
set "IN=%~1"
if "%~2"=="" (set "OUT=%~dpn1-aes.p12") else (set "OUT=%~2")

if not exist "%IN%" (
    echo Soubor %IN% neexistuje
    exit /b 1
)
if exist "%OUT%" (
    echo Vystupni soubor %OUT% uz existuje, neprepisuji ho
    exit /b 1
)

rem Heslo se cte do promenne prostredi, openssl si ho bere primo z ni (env:P12PASS),
rem takze specialni znaky v hesle nevadi. Pri psani je heslo videt.
if not defined P12PASS set /p "P12PASS=Heslo k certifikatu: "

rem openssl pkcs12 -export cte vstup dvakrat (klic a certifikaty), takze nejde pouzit
rem roura - mezivysledek jde do docasneho PEM s klicem zasifrovanym AES-256 stejnym heslem
set "TMPPEM=%TEMP%\p12-convert-%RANDOM%%RANDOM%.pem"

openssl pkcs12 -legacy -in "%IN%" -passin env:P12PASS -out "%TMPPEM%" -aes256 -passout env:P12PASS
if errorlevel 1 goto fail
openssl pkcs12 -export -in "%TMPPEM%" -passin env:P12PASS -out "%OUT%" -passout env:P12PASS -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256
if errorlevel 1 goto fail
del "%TMPPEM%"

rem Kontrola: novy soubor musi jit otevrit bez legacy provideru
openssl pkcs12 -in "%OUT%" -noout -passin env:P12PASS >nul 2>&1
if errorlevel 1 (
    echo Prevedeny soubor nejde otevrit, mazu ho
    del "%OUT%"
    exit /b 1
)

echo Hotovo: %OUT%
endlocal
exit /b 0

:fail
echo Prevod selhal (chybne heslo nebo poskozeny soubor)
if exist "%TMPPEM%" del "%TMPPEM%"
if exist "%OUT%" del "%OUT%"
endlocal
exit /b 1
