/***************************************************************
 * Name:      eet.h
 * Author:    David Vachulka (archdvx@dxsolutions.org)
 * Copyright: 2016
 * License:   LGPL3
 * Updated for EET 2.0 (v4 interface, 2026)
 **************************************************************/

#ifndef EET_H
#define EET_H

#include <string>
#include <vector>
#include <map>
#include <new>
#include <openssl/evp.h>

#ifdef _WIN32
# ifdef eetpp_EXPORTS
#  define EETPP_EXPORT __declspec(dllexport)
# else
#  define EETPP_EXPORT __declspec(dllimport)
#endif
#else
# define EETPP_EXPORT
#endif

#define EETVERSION "2.00.0"
#define PGURL "https://pg.trzbyeet.gov.cz:443/eet/services/EETServiceSOAP/v4"
#define PRODUKCNIURL "https://trzbyeet.gov.cz:443/eet/services/EETServiceSOAP/v4"
#define SOAPACTION "http://fs.gov.cz/eet/OdeslaniTrzby"

typedef std::map<std::string,std::string> StringMap;
typedef std::pair<std::string,std::string> StringPair;
typedef std::map<std::string,std::string>::iterator StringIt;

/*! \file */

/*!
 * \defgroup Enumerations
 * \brief Public enumerations
 */

/*!
 * \enum OVERENI
 * \brief Příznak ověřovacího módu odesílání
 * \ingroup Enumerations
 */
enum OVERENI {
    PRODUKCNI = 0,
    OVEROVACI
};

/*!
 * \enum ZASLANI
 * \brief První zaslání údajů o tržbě
 * \ingroup Enumerations
 */
enum ZASLANI {
    OPAKOVANE = 0,
    PRVNI
};

/*!
 * \enum EETCODE
 * \brief Návratové kódy funkce sendTrzba
 * \ingroup Enumerations
 */
enum EETCODE {
    EET_OK = 0, /**< Tržba odeslána bez chyb a varování nebo nastavení parametrů bez chyb */
    EET_VAROVANI, /**< Tržba odeslána s varováním */
    EET_CHYBA, /**< Tržba odeslána s chybou */
    EET_OVERENO, /**< Tržba v ověřovacím módu odeslána úspěšně */
    EET_OVERENO_SVAROVANIM, /**< Tržba v ověřovacím módu odeslána s varováním */
    EET_ERROR /**< Chyba socketu, chybný certifikát, chybně zadané EIČ atd. */
};

class EETPP_EXPORT EetData
{
public:
    /*!
     * \brief Prázdný konstruktor třídy EetData
     */
    EetData();
    /*!
     * \brief Konstruktor třídy EetData
     * \param poradCis Pořadové číslo účtenky
     * \param celkTrzba Celková částka tržby
     * \param prvniZaslani První zaslání údajů o tržbě
     * \param datOdesl Datum a čas odeslání zprávy
     * \param datTrzby Datum a čas přijetí tržby
     * \param urcenoCerpZuct Celková částka plateb určená k následnému čerpání nebo zúčtování
     * \param cerpZuct Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby
     */
    EetData(const std::string &poradCis, double celkTrzba, const ZASLANI &prvniZaslani=PRVNI,
            time_t datOdesl=::time(NULL), time_t datTrzby=::time(NULL),
            double *urcenoCerpZuct=NULL, double *cerpZuct=NULL);

    /*!
     * \brief Kontrola dat tržby podle xsd schématu
     */
    EETCODE checkData();
    /*!
     * \brief Format řetězců
     */
    static std::string formatString(const char *fmt, ...);
    //Getters & setters
    /*!
     * \brief Text chyby při EET_ERROR
     */
    std::string getChyba();
    /*!
     * \brief Datum a čas odeslání zprávy
     */
    std::string getDatOdesl() const;
    /*!
     * \brief Datum a čas odeslání zprávy
     */
    EETCODE setDatOdesl(const std::string &datOdesl);
    /*!
     * \brief Datum a čas odeslání zprávy
     */
    EETCODE setDatOdesl(time_t datOdesl);
    /*!
     * \brief První zaslání údajů o tržbě
     */
    ZASLANI getPrvniZaslani() const;
    /*!
     * \brief První zaslání údajů o tržbě
     */
    EETCODE setPrvniZaslani(const ZASLANI &prvniZaslani);
    /*!
     * \brief Pořadové číslo účtenky
     */
    std::string getPoradCis() const;
    /*!
     * \brief Pořadové číslo účtenky
     */
    EETCODE setPoradCis(const std::string &poradCis);
    /*!
     * \brief Datum a čas přijetí tržby
     */
    std::string getDatTrzby() const;
    /*!
     * \brief Datum a čas přijetí tržby
     */
    EETCODE setDatTrzby(const std::string &datTrzby);
    /*!
     * \brief Datum a čas přijetí tržby
     */
    EETCODE setDatTrzby(time_t datTrzby);
    /*!
     * \brief Celková částka tržby
     */
    std::string getCelkTrzba() const;
    /*!
     * \brief Celková částka tržby
     */
    EETCODE setCelkTrzba(const std::string &celkTrzba);
    /*!
     * \brief Celková částka tržby
     */
    EETCODE setCelkTrzba(double celkTrzba);
    /*!
     * \brief Celková částka plateb určená k následnému čerpání nebo zúčtování
     */
    std::string getUrcenoCerpZuct() const;
    /*!
     * \brief Celková částka plateb určená k následnému čerpání nebo zúčtování
     */
    EETCODE setUrcenoCerpZuct(const std::string &urcenoCerpZuct);
    /*!
     * \brief Celková částka plateb určená k následnému čerpání nebo zúčtování
     */
    EETCODE setUrcenoCerpZuct(double urcenoCerpZuct);
    /*!
     * \brief Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby
     */
    std::string getCerpZuct() const;
    /*!
     * \brief Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby
     */
    EETCODE setCerpZuct(const std::string &cerpZuct);
    /*!
     * \brief Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby
     */
    EETCODE setCerpZuct(double cerpZuct);
private:
    //Hlavicka - start
    std::string m_datOdesl;
    ZASLANI m_prvniZaslani;
    //Hlavicka - end
    //Data - start
    std::string m_poradCis;
    std::string m_datTrzby;
    std::string m_celkTrzba;
    // Optional Data - start
    std::string m_urcenoCerpZuct;
    std::string m_cerpZuct;
    // Optional Data - end
    //Data - end
    std::string m_chyba;

    /*!
     * \brief Format Finanční položky tržby
     */
    std::string formatDouble(double val);
    /*!
     * \brief Kontrola Finanční položky tržby
     */
    bool regexDouble(const std::string &text);
    /*!
     * \brief Format Datum a čas odeslání zprávy, Datum a čas přijetí tržby
     */
    std::string formatTime(time_t time);
    /*!
     * \brief Kontrola Datum a čas odeslání zprávy, Datum a čas přijetí tržby
     */
    bool regexTime(const std::string &text);
    /*!
     * \brief Kontrola Pořadové číslo účtenky
     */
    bool regexString25(const std::string &text);
};

class EETPP_EXPORT Eet
{
public:
    /*!
     * \brief Prázdný konstruktor třídy Eet
     */
    Eet();
    /*!
     * \brief Konstruktor třídy Eet
     * \param eicPopl EIČ poplatníka (DIČ, nebo CZ+rodné číslo, nebo CZ+VČP)
     * \param idJednotky Označení evidenční jednotky
     * \param cert Cesta k certifikátu
     * \param pass Heslo certifikátu
     * \param idPokl Označení pokladního zařízení
     * \param eicPoverujiciho EIČ pověřujícího poplatníka
     * \param overeni Příznak ověřovacího módu odesílání
     * \param playground Nastavení playground prostředí
     */
    Eet(const std::string &eicPopl, int idJednotky, const std::string &cert, const std::string &pass, const std::string &idPokl="", const std::string &eicPoverujiciho="",
        const OVERENI &overeni=PRODUKCNI, bool playground=false);

    /*!
     * \brief Certfikát a jeho heslo
     * \param cert Cesta k certifikátu
     * \param pass Heslo certifikátu
     */
    EETCODE setCertPass(const std::string &cert, const std::string &pass);
    /*!
     * \brief Odešle tržbu
     * \param data Data tržby
     */
    EETCODE sendTrzba(const EetData &data);
    /*!
     * \brief Odešle tržbu
     * \param idPokl Označení pokladního zařízení
     * \param data Data tržby
     */
    EETCODE sendTrzba(const std::string &idPokl, const EetData &data);
    //Setters
    /*!
     * \brief Příznak ověřovacího módu odesílání - Optional
     */
    EETCODE setOvereni(const OVERENI &overeni);
    /*!
     * \brief EIČ poplatníka
     */
    EETCODE setEicPopl(const std::string &eicPopl);
    /*!
     * \brief EIČ pověřujícího poplatníka - Optional
     */
    EETCODE setEicPoverujiciho(const std::string &eicPoverujiciho);
    /*!
     * \brief Příznak, že evidovaná tržba plyne více poplatníkům - Optional
     */
    EETCODE setPovereniVicePopl(bool povereniVicePopl);
    /*!
     * \brief Označení evidenční jednotky
     */
    EETCODE setIdJednotky(int idJednotky);
    /*!
     * \brief Označení pokladního zařízení
     */
    EETCODE setIdPokl(const std::string &idPokl);
    /*!
     * \brief Nastavení playground prostředí
     */
    void setPlayground(bool playground);
    //Getters
    /*!
     * \brief Potvrzovací kód (POK)
     */
    std::string getPok();
    /*!
     * \brief Potvrzovací kód (POK) - alias pro zpětnou kompatibilitu s EET 1.0 API
     */
    std::string getFik();
    /*!
     * \brief Text chyby při EET_CHYBA nebo EET_ERROR
     */
    std::string getChyba();
    /*!
     * \brief Text varování při EET_VAROVANI
     */
    std::string getVarovani();
    /*!
     * \brief Verze eetpp
     */
    std::string getVersion();
    /*!
     * \brief Verze OpenSSL
     */
    std::string getOpensslVersion();
    /*!
     * \brief Verze Curl
     */
    std::string getCurlVersion();
private:
    //Hlavicka - start
    OVERENI m_overeni;
    //Hlavicka - end
    //Data - start
    std::string m_eicPopl;
    std::string m_eicPoverujiciho;
    bool m_povereniVicePopl;
    int m_idJednotky;
    std::string m_idPokl;
    //Data - end
    std::string m_certPath;
    std::string m_pass;
    char *m_key;
    char *m_cert;
    StringMap m_values;
    std::string m_pok;
    std::string m_chyba;
    std::string m_varovani;
    bool m_playground;

    EETCODE sendTrzbaImpl(EetData data);
    bool createKeyCert();
    EVP_PKEY *createPKey(bool pub);
    std::vector<unsigned char> createSignature(const std::string &plaintext);
    std::vector<unsigned char> sha256(const std::string &str);
    void showDebug(const std::string &text);
    std::string uuid4();
    std::string base64Encode(std::vector<unsigned char> data);
    std::string byte2Hex(std::vector<unsigned char> data);
    std::string formatCertificate();
    /*!
     * \brief Format První zaslání údajů o tržbě, Příznak ověřovacího módu odesílání, Pověření více poplatníky
     */
    std::string formatBool(bool value);
    std::string fillTemplate(const std::string &templ);
    void parseResponse(const std::string &response, OVERENI overeni);
    bool regexString20(const std::string &text);
    bool regexEic(const std::string &text);
    bool checkIcChecksum(const std::string &ic);
};

#endif
