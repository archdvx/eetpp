/***************************************************************
 * Name:      eet.h
 * Author:    David Vachulka (arch_dvx@users.sourceforge.net)
 * Copyright: 2016
 * License:   LGPL3
 **************************************************************/

#ifndef EET_H
#define EET_H

#include <string>
#include <vector>
#include <map>
#include <new>
#include <openssl/rsa.h>

#ifdef __WIN32
# ifdef eetpp_EXPORTS
#  define EETPP_EXPORT __declspec(dllexport)
# else
#  define EETPP_EXPORT __declspec(dllimport)
#endif
#else
# define EETPP_EXPORT
#endif

#define EETVERSION "1.00.0"
#define PGURL "https://pg.eet.cz:443/eet/services/EETServiceSOAP/v3"
#define PRODUKCNIURL "https://prod.eet.cz/eet/services/EETServiceSOAP/v3"

typedef std::map<std::string,std::string> StringMap;
typedef std::pair<std::string,std::string> StringPair;
typedef std::map<std::string,std::string>::iterator StringIt;

/*! \file */

/*!
 * \defgroup Enumerations
 * \brief Public enumerations
 */

/*!
 * \enum REZIM
 * \brief Režim tržby
 * \ingroup Enumerations
 */
enum REZIM {
    STANDARDNI = 0,
    ZJEDNODUSENY
};

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
    EET_ERROR /**< Chyba socketu, chybný certifikát, chybně zadané DIC atd. */
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
     * \param zaklNepodlDph Celková částka plnění osvobozených od DPH, ostatních plnění
     * \param zaklDan1 Celkový základ daně se základní sazbou DPH
     * \param dan1 Celková DPH se základní sazbou
     * \param zaklDan2 Celkový základ daně s první sníženou sazbou DPH
     * \param dan2 Celková DPH s první sníženou sazbou
     * \param zaklDan3 Celkový základ daně s druhou sníženou sazbou DPH
     * \param dan3 Celková DPH s druhou sníženou sazbou
     * \param prvniZaslani První zaslání údajů o tržbě
     * \param rezim Režim tržby
     * \param datOdesl Datum a čas odeslání zprávy
     * \param datTrzby Datum a čas přijetí tržby
     * \param cestSluz Celková částka v režimu DPH pro cestovní službu
     * \param pouzitZboz1 Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou
     * \param pouzitZboz2 Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou
     * \param pouzitZboz3 Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou
     * \param urcenoCerpZuct Celková částka plateb určená k následnému čerpání nebo zúčtování
     * \param cerpZuct Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby
     */
    EetData(const std::string &poradCis, double celkTrzba, double *zaklNepodlDph=NULL, double *zaklDan1=NULL, double *dan1=NULL, double *zaklDan2=NULL, double *dan2=NULL,
            double *zaklDan3=NULL, double *dan3=NULL, const ZASLANI &prvniZaslani=PRVNI, const REZIM &rezim=STANDARDNI, time_t datOdesl=::time(NULL), time_t datTrzby=::time(NULL),
            double *cestSluz=NULL, double *pouzitZboz1=NULL, double *pouzitZboz2=NULL, double *pouzitZboz3=NULL,
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
     * \brief Režim tržby
     */
    REZIM getRezim() const;
    /*!
     * \brief Režim tržby
     */
    EETCODE setRezim(const REZIM &rezim);
    /*!
     * \brief Celková částka plnění osvobozených od DPH, ostatních plnění
     */
    std::string getZaklNepodlDph() const;
    /*!
     * \brief Celková částka plnění osvobozených od DPH, ostatních plnění
     */
    EETCODE setZaklNepodlDph(const std::string &zaklNepodlDph);
    /*!
     * \brief Celková částka plnění osvobozených od DPH, ostatních plnění
     */
    EETCODE setZaklNepodlDph(double zaklNepodlDph);
    /*!
     * \brief Celkový základ daně se základní sazbou DPH
     */
    std::string getZaklDan1() const;
    /*!
     * \brief Celkový základ daně se základní sazbou DPH
     */
    EETCODE setZaklDan1(const std::string &zaklDan1);
    /*!
     * \brief Celkový základ daně se základní sazbou DPH
     */
    EETCODE setZaklDan1(double zaklDan1);
    /*!
     * \brief Celková DPH se základní sazbou
     */
    std::string getDan1() const;
    /*!
     * \brief Celková DPH se základní sazbou
     */
    EETCODE setDan1(const std::string &dan1);
    /*!
     * \brief Celková DPH se základní sazbou
     */
    EETCODE setDan1(double dan1);
    /*!
     * \brief Celkový základ daně s první sníženou sazbou DPH
     */
    std::string getZaklDan2() const;
    /*!
     * \brief Celkový základ daně s první sníženou sazbou DPH
     */
    EETCODE setZaklDan2(const std::string &zaklDan2);
    /*!
     * \brief Celkový základ daně s první sníženou sazbou DPH
     */
    EETCODE setZaklDan2(double zaklDan2);
    /*!
     * \brief Celková DPH s první sníženou sazbou
     */
    std::string getDan2() const;
    /*!
     * \brief Celková DPH s první sníženou sazbou
     */
    EETCODE setDan2(const std::string &dan2);
    /*!
     * \brief Celková DPH s první sníženou sazbou
     */
    EETCODE setDan2(double dan2);
    /*!
     * \brief Celkový základ daně s druhou sníženou sazbou DPH
     */
    std::string getZaklDan3() const;
    /*!
     * \brief Celkový základ daně s druhou sníženou sazbou DPH
     */
    EETCODE setZaklDan3(const std::string &zaklDan3);
    /*!
     * \brief Celkový základ daně s druhou sníženou sazbou DPH
     */
    EETCODE setZaklDan3(double zaklDan3);
    /*!
     * \brief Celková DPH s druhou sníženou sazbou
     */
    std::string getDan3() const;
    /*!
     * \brief Celková DPH s druhou sníženou sazbou
     */
    EETCODE setDan3(const std::string &dan3);
    /*!
     * \brief Celková DPH s druhou sníženou sazbou
     */
    EETCODE setDan3(double dan3);
    /*!
     * \brief Celková částka v režimu DPH pro cestovní službu
     */
    std::string getCestSluz() const;
    /*!
     * \brief Celková částka v režimu DPH pro cestovní službu
     */
    EETCODE setCestSluz(const std::string &cestSluz);
    /*!
     * \brief Celková částka v režimu DPH pro cestovní službu
     */
    EETCODE setCestSluz(double cestSluz);
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou
     */
    std::string getPouzitZboz1() const;
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou
     */
    EETCODE setPouzitZboz1(const std::string &pouzitZboz1);
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou
     */
    EETCODE setPouzitZboz1(double pouzitZboz1);
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou
     */
    std::string getPouzitZboz2() const;
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou
     */
    EETCODE setPouzitZboz2(const std::string &pouzitZboz2);
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou
     */
    EETCODE setPouzitZboz2(double pouzitZboz2);
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou
     */
    std::string getPouzitZboz3() const;
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou
     */
    EETCODE setPouzitZboz3(const std::string &pouzitZboz3);
    /*!
     * \brief Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou
     */
    EETCODE setPouzitZboz3(double pouzitZboz3);
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
    REZIM m_rezim;
    // Optional Data - start
    std::string m_zaklNepodlDph;
    std::string m_zaklDan1;
    std::string m_dan1;
    std::string m_zaklDan2;
    std::string m_dan2;
    std::string m_zaklDan3;
    std::string m_dan3;
    std::string m_cestSluz;
    std::string m_pouzitZboz1;
    std::string m_pouzitZboz2;
    std::string m_pouzitZboz3;
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
     * \param dicPopl DIČ poplatníka
     * \param idProvoz Označení provozovny
     * \param cert Cesta k certifikátu
     * \param pass Heslo certifikátu
     * \param idPokl Označení pokladního zařízení
     * \param dicPoverujiciho DIČ pověřujícího poplatníka
     * \param overeni Příznak ověřovacího módu odesílání
     * \param rezim Režim tržby
     * \param playground Nastavení playground prostředí
     */
    Eet(const std::string &dicPopl, int idProvoz, const std::string &cert, const std::string &pass, const std::string &idPokl="", const std::string &dicPoverujiciho="",
        const OVERENI &overeni=PRODUKCNI, const REZIM &rezim=STANDARDNI, bool playground=false);

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
     * \brief DIČ poplatníka
     */
    EETCODE setDicPopl(const std::string &dicPopl);
    /*!
     * \brief DIČ pověřujícího poplatníka - Optional
     */
    EETCODE setDicPoverujiciho(const std::string &dicPoverujiciho);
    /*!
     * \brief Označení provozovny
     */
    EETCODE setIdProvoz(int idProvoz);
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
     * \brief Podpisový kód poplatníka (PKP)
     */
    std::string getPkp();
    /*!
     * \brief Bezpečnostní kód poplatníka (BKP)
     */
    std::string getBkp();
    /*!
     * \brief Fiskální identifikační kód (FIK)
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
    std::string m_dicPopl;
    std::string m_dicPoverujiciho;
    int m_idProvoz;
    std::string m_idPokl;
    REZIM m_rezim;
    //Data - end
    //Kontrolni kody - start
    //Generovany funkci createPkpBkp
    std::vector<unsigned char> m_pkp;
    std::vector<unsigned char> m_bkp;
    //Kontrolni kody - end
    std::string m_certPath;
    std::string m_pass;
    char *m_key;
    char *m_cert;
    StringMap m_values;
    std::string m_fik;
    std::string m_chyba;
    std::string m_varovani;
    bool m_playground;

    EETCODE sendTrzbaImpl(EetData data);
    bool createKeyCert();
    RSA *createRSA(bool pub);
    void createPkpBkp(const std::string &plaintext);
    bool createPkp(std::vector<unsigned char> data);
    std::vector<unsigned char> createSignature(const std::string &plaintext);
    std::vector<unsigned char> sha1(std::vector<unsigned char> data);
    std::vector<unsigned char> sha256(const std::string &str);
    void showDebug(const std::string &text);
    std::string uuid4();
    std::string base64Encode(std::vector<unsigned char> data);
    std::string byte2Hex(std::vector<unsigned char> data);
    std::string formatPkp();
    std::string formatBkp();
    std::string formatCertificate();
    /*!
     * \brief Format První zaslání údajů o tržbě, Příznak ověřovacího módu odesílání
     */
    std::string formatBool(bool value);
    std::string fillTemplate(const std::string &templ);
    void parseResponse(const std::string &response);
    bool regexString20(const std::string &text);
    bool regexDic(const std::string &text);
};

#endif
