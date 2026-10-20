/***************************************************************
 * Name:      eet.cpp
 * Author:    David Vachulka (archdvx@dxsolutions.org)
 * Copyright: 2016
 * License:   LGPL3
 * Updated for EET 2.0 (v4 interface, 2026)
 **************************************************************/

#include "eet.h"
#include "templates.h"
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <stdarg.h>
#include <sstream>
#include <string.h>
#include <algorithm>
#include <cstdlib>
#include <cmath>
#include <cctype>
#include <ctime>
#include <regex>
#include <locale>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <curl/curl.h>
#ifdef _WIN32
#include <windows.h>
#endif

#define EET_DEFAULT_TIMEOUT 10000L

static size_t curlCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

Eet::Eet()
    : m_overeni(PRODUKCNI), m_eicPopl(""), m_eicPoverujiciho(""), m_povereniVicePopl(false), m_idJednotky(0), m_idPokl(""), m_certPath(""), m_pass(""),
      m_playground(false), m_timeout(EET_DEFAULT_TIMEOUT)
{
}

Eet::Eet(const std::string &eicPopl, int idJednotky, const std::string &cert, const std::string &pass, const std::string &idPokl, const std::string &eicPoverujiciho,
         const OVERENI &overeni, bool playground)
    : m_overeni(overeni), m_eicPopl(eicPopl), m_eicPoverujiciho(eicPoverujiciho), m_povereniVicePopl(false), m_idJednotky(idJednotky), m_idPokl(idPokl), m_certPath(cert), m_pass(pass),
      m_playground(playground), m_timeout(EET_DEFAULT_TIMEOUT)
{
    createKeyCert();
}

EETCODE Eet::setCertPass(const std::string &cert, const std::string &pass)
{
    m_certPath = cert;
    m_pass = pass;
    if(!createKeyCert())
    {
        return EET_ERROR;
    }
    return EET_OK;
}

EETCODE Eet::sendTrzba(const EetData &data)
{
    return sendTrzbaImpl(data);
}

EETCODE Eet::sendTrzba(const std::string &idPokl, const EetData &data)
{
    if(!regexString20(idPokl))
    {
        m_chyba = "Chyba v Označení pokladního zařízení";
        return EET_ERROR;
    }
    m_idPokl = idPokl;
    return sendTrzbaImpl(data);
}

EETCODE Eet::setOvereni(const OVERENI &overeni)
{
    if(overeni<PRODUKCNI || overeni>OVEROVACI)
    {
        m_chyba = "Chyba v Příznak ověřovacího módu odesílání";
        return EET_ERROR;
    }
    m_overeni = overeni;
    return EET_OK;
}

EETCODE Eet::setEicPopl(const std::string &eicPopl)
{
    if(!regexEic(eicPopl))
    {
        m_chyba = "Chyba v EIČ poplatníka";
        return EET_ERROR;
    }
    m_eicPopl = eicPopl;
    return EET_OK;
}

EETCODE Eet::setEicPoverujiciho(const std::string &eicPoverujiciho)
{
    if(eicPoverujiciho.empty())
    {
        m_eicPoverujiciho = "";
        return EET_OK;
    }
    if(!regexEic(eicPoverujiciho))
    {
        m_chyba = "Chyba v EIČ pověřujícího poplatníka";
        return EET_ERROR;
    }
    m_eicPoverujiciho = eicPoverujiciho;
    return EET_OK;
}

EETCODE Eet::setPovereniVicePopl(bool povereniVicePopl)
{
    m_povereniVicePopl = povereniVicePopl;
    return EET_OK;
}

EETCODE Eet::setIdJednotky(int idJednotky)
{
    if(idJednotky<1 || idJednotky>999999999)
    {
        m_chyba = "Chyba v Označení evidenční jednotky";
        return EET_ERROR;
    }
    m_idJednotky = idJednotky;
    return EET_OK;
}

EETCODE Eet::setIdPokl(const std::string &idPokl)
{
    if(!regexString20(idPokl))
    {
        m_chyba = "Chyba v Označení pokladního zařízení";
        return EET_ERROR;
    }
    m_idPokl = idPokl;
    return EET_OK;
}

void Eet::setPlayground(bool playground)
{
    m_playground = playground;
}

void Eet::setTimeout(long timeoutMs)
{
    m_timeout = timeoutMs;
}

std::string Eet::getPok()
{
    return m_pok;
}

std::string Eet::getFik()
{
    // Zpětná kompatibilita s API EET 1.0 - vrací potvrzovací kód (POK)
    return m_pok;
}

std::string Eet::getChyba()
{
    return m_chyba;
}

std::string Eet::getVarovani()
{
    return m_varovani;
}

std::string Eet::getVersion()
{
    return EETVERSION;
}

std::string Eet::getOpensslVersion()
{
    return OPENSSL_VERSION_TEXT;
}

std::string Eet::getCurlVersion()
{
    return curl_version();
}

EETCODE Eet::sendTrzbaImpl(EetData data)
{
    if(m_cert.empty() || !m_pkey)
    {
        m_chyba = m_certChyba.empty() ? "Chyba certifikátu" : m_certChyba;
        return EET_ERROR;
    }

    if(m_overeni<PRODUKCNI || m_overeni>OVEROVACI)
    {
        m_chyba = "Chyba v Příznak ověřovacího módu odesílání";
        return EET_ERROR;
    }

    if(!regexEic(m_eicPopl))
    {
        m_chyba = "Chyba v EIČ poplatníka";
        return EET_ERROR;
    }

    if(m_idJednotky<1 || m_idJednotky>999999999)
    {
        m_chyba = "Chyba v Označení evidenční jednotky";
        return EET_ERROR;
    }

    if(!regexString20(m_idPokl))
    {
        m_chyba = "Chyba v Označení pokladního zařízení";
        return EET_ERROR;
    }

    if(data.checkData() != EET_OK)
    {
        m_chyba = data.getChyba();
        return EET_ERROR;
    }

    m_values.clear();
    m_values.insert(StringPair("uuid_zpravy", uuid4()));
    m_values.insert(StringPair("dat_odesl", data.getDatOdesl()));
    m_values.insert(StringPair("prvni_zaslani", formatBool(data.getPrvniZaslani())));
    m_values.insert(StringPair("overeni", formatBool(m_overeni)));
    m_values.insert(StringPair("certb64", formatCertificate()));
    m_values.insert(StringPair("eic_popl", m_eicPopl));
    m_values.insert(StringPair("eic_poverujiciho", m_eicPoverujiciho));
    m_values.insert(StringPair("povereni_vice_popl", m_eicPoverujiciho.empty() && !m_povereniVicePopl ? "" : formatBool(m_povereniVicePopl)));
    m_values.insert(StringPair("id_jednotky", EetData::formatString("%d", m_idJednotky)));
    m_values.insert(StringPair("id_pokl", m_idPokl));
    m_values.insert(StringPair("porad_cis", data.getPoradCis()));
    m_values.insert(StringPair("dat_trzby", data.getDatTrzby()));
    m_values.insert(StringPair("celk_trzba", data.getCelkTrzba()));
    m_values.insert(StringPair("urceno_cerp_zuct", data.getUrcenoCerpZuct()));
    m_values.insert(StringPair("cerp_zuct", data.getCerpZuct()));

    std::string templateBody = fillTemplate(template_body);
    m_values.insert(StringPair("soap:Body", templateBody));
    m_values.insert(StringPair("digest", base64Encode(sha256(templateBody))));

    std::string templateSignature = fillTemplate(template_signature);
    m_values.insert(StringPair("signature", base64Encode(createSignature(templateSignature))));

    std::string templateRequest = fillTemplate(template_request);
    showDebug("templateRequest:\n");
    showDebug(templateRequest);

    std::string response;
    long httpCode = 0;
    CURL *curl = curl_easy_init();
    if(!curl)
    {
        m_chyba = "Nepodařilo se inicializovat curl";
        return EET_ERROR;
    }
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, EetData::formatString("SOAPAction: %s", SOAPACTION).c_str());
    headers = curl_slist_append(headers, "Content-Type: text/xml; charset=utf-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, m_playground?PGURL:PRODUKCNIURL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, templateRequest.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)templateRequest.size());
    curl_easy_setopt(curl, CURLOPT_CRLF, 0L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
#if defined(_WIN32) && defined(CURLSSLOPT_NATIVE_CA)
    // Mimo MSYS2 curl nenajde svůj ca-bundle.crt - použije se úložiště certifikátů Windows
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA);
#endif
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, m_timeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, m_timeout);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode res = curl_easy_perform(curl);
    if(res == CURLE_OK)
    {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if(res != CURLE_OK)
    {
        m_chyba = curl_easy_strerror(res);
        return EET_ERROR;
    }
    showDebug("Response:");
    showDebug(response);
    parseResponse(response, m_overeni);
    // SOAP Fault chodí s HTTP 500 a tělem - když z něj nic nevyčteme, nahlásíme aspoň status
    if(httpCode != 200 && m_chyba.empty() && m_pok.empty())
    {
        m_chyba = EetData::formatString("Server vrátil HTTP %ld", httpCode);
        return EET_ERROR;
    }
    if(m_overeni == OVEROVACI && !m_pok.empty())
    {
        m_pok.clear();
        if(!m_varovani.empty()) return EET_OVERENO_SVAROVANIM;
        else return EET_OVERENO;
    }
    if(!m_chyba.empty()) return EET_CHYBA;
    if(!m_varovani.empty()) return EET_VAROVANI;
    if(m_pok.empty())
    {
        m_chyba = "Nepodařilo se získat POK";
        return EET_ERROR;
    }
    m_chyba.clear();
    m_varovani.clear();
    return EET_OK;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// Řada reálných produkčních .p12 certifikátů (např. od Finanční správy) je
// zašifrována starším algoritmem RC2-40-CBC. OpenSSL 3.0 tyto algoritmy
// přesunulo do tzv. "legacy" provideru, který se defaultně nenačítá - bez
// něj parsování takového PKCS#12 souboru selže s chybou "unsupported".
struct ProvidersStatus
{
    bool legacy;
    std::string warning;    // prázdný řetězec znamená úspěch
};

static ProvidersStatus loadOpensslProviders()
{
    std::string warning;
    bool legacy = OSSL_PROVIDER_load(nullptr, "legacy") != nullptr;
#ifdef _WIN32
    if(!legacy)
    {
        // Mimo MSYS2 neplatí cesta k ossl-modules zapečená při kompilaci OpenSSL,
        // legacy.dll se proto hledá v podadresáři ossl-modules vedle exe
        char path[MAX_PATH];
        DWORD len = GetModuleFileNameA(nullptr, path, MAX_PATH);
        if(len > 0 && len < MAX_PATH)
        {
            std::string dir(path, len);
            dir = dir.substr(0, dir.find_last_of("\\/") + 1) + "ossl-modules";
            OSSL_PROVIDER_set_default_search_path(nullptr, dir.c_str());
            legacy = OSSL_PROVIDER_load(nullptr, "legacy") != nullptr;
        }
    }
#endif
    if(!legacy)
    {
        warning += "Nepodařilo se načíst OpenSSL legacy provider (starší RC2/3DES šifrování v PKCS#12 nemusí fungovat)\n";
    }
    if(OSSL_PROVIDER_load(nullptr, "default") == nullptr)
    {
        warning += "Nepodařilo se načíst OpenSSL default provider\n";
    }
    ERR_clear_error();
    ProvidersStatus status;
    status.legacy = legacy;
    status.warning = warning;
    return status;
}
#endif

static std::string bioToString(BIO *bio)
{
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if(len <= 0 || data == nullptr) return std::string();
    return std::string(data, len);
}

bool Eet::createKeyCert()
{
    m_pkey.reset();
    m_cert.clear();
    m_certChyba.clear();
    FILE *fp;
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    PKCS12 *p12;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Heslo je potřeba jen pro PKCS12_parse, pak se přepíše a zahodí
    auto clearPass = [this]() {
        if(!m_pass.empty()) OPENSSL_cleanse(&m_pass[0], m_pass.size());
        m_pass.clear();
    };
    auto fail = [this, &clearPass](const std::string &chyba) {
        clearPass();
        m_chyba = chyba;
        m_certChyba = chyba;
        showDebug(chyba);
        return false;
    };

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Inicializace statické proměnné je od C++11 thread-safe a proběhne jen jednou
    static const ProvidersStatus providers = loadOpensslProviders();
    showDebug(providers.warning);
    const bool legacyAvailable = providers.legacy;
#else
    // OpenSSL < 3.0 umí RC2/3DES bez legacy provideru
    const bool legacyAvailable = true;
#endif

    #ifndef _WIN32
        fp = fopen(m_certPath.c_str(), "rb");
    #else
        // On Windows, non-ascii characters in path don't work with fopen(). Thus use _wfopen() instead.
        std::wstring filePathW(m_certPath.size(), L'\0');
        int newSize = MultiByteToWideChar(CP_UTF8, 0, m_certPath.c_str(), (int)m_certPath.length(), &filePathW[0], (int)filePathW.size());
        filePathW.resize(newSize);
        fp = _wfopen(filePathW.c_str(), L"rb");
    #endif

    if(!fp)
    {
        return fail(EetData::formatString("Chyba při otevírání souboru certifikátu %s", m_certPath.c_str()));
    }
    p12 = d2i_PKCS12_fp(fp, nullptr);
    fclose (fp);
    if(!p12)
    {
        ERR_print_errors_fp(stderr);
        return fail("Chyba při čtení PKCS#12 souboru");
    }
    if(!PKCS12_parse(p12, m_pass.c_str(), &pkey, &cert, &ca))
    {
        // MAC (HMAC-SHA1/SHA256) jde ověřit i bez legacy provideru, takže odliší chybné heslo
        // od šifrování, které aktuální OpenSSL neumí
        bool hasMac = PKCS12_mac_present(p12) == 1;
        bool passOk = hasMac && PKCS12_verify_mac(p12, m_pass.c_str(), -1) == 1;
        PKCS12_free(p12);
        ERR_print_errors_fp(stderr);
        if(hasMac && !passOk)
        {
            return fail("Chyba při parsování PKCS#12 souboru (chybné heslo)");
        }
        if(passOk && !legacyAvailable)
        {
            return fail("Certifikát používá starší šifrování (RC2/3DES) a OpenSSL legacy provider není dostupný. "
                        "Převeďte certifikát na nový formát (p12-convert.sh / p12-convert.bat).");
        }
        return fail("Chyba při parsování PKCS#12 souboru (nepodporované šifrování nebo poškozený soubor)");
    }
    PKCS12_free(p12);
    clearPass();
    if(pkey)
    {
        // Klíč se drží jen jako EVP_PKEY - EVP_PKEY_free ho při uvolnění v paměti přepíše
        m_pkey.reset(pkey, EVP_PKEY_free);
    }
    if(cert)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if(bio && PEM_write_bio_X509(bio, cert))
        {
            m_cert = bioToString(bio);
        }
        BIO_free(bio);
    }
    sk_X509_pop_free(ca, X509_free);
    X509_free(cert);
    if(!m_pkey || m_cert.empty())
    {
        m_pkey.reset();
        m_cert.clear();
        return fail("PKCS#12 soubor neobsahuje privátní klíč nebo certifikát");
    }
    return true;
}

std::vector<unsigned char> Eet::createSignature(const std::string &plaintext)
{
    std::vector<unsigned char> signature;
    EVP_PKEY *pkey = m_pkey.get();
    if(pkey == nullptr) return signature;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(mdctx == nullptr)
    {
        showDebug("Failed to create EVP_MD_CTX");
        return signature;
    }

    const unsigned char *tbs = (const unsigned char *)plaintext.c_str();
    size_t tbslen = plaintext.size();
    size_t siglen = 0;
    bool ok = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) == 1
              && EVP_DigestSign(mdctx, nullptr, &siglen, tbs, tbslen) == 1;

    if(ok)
    {
        signature.resize(siglen);
        if(EVP_DigestSign(mdctx, &signature[0], &siglen, tbs, tbslen) != 1)
        {
            showDebug("Neco se podelalo");
            signature.clear();
        }
        else
        {
            signature.resize(siglen);
        }
    }
    else
    {
        showDebug("Neco se podelalo");
    }

    EVP_MD_CTX_free(mdctx);
    return signature;
}

std::vector<unsigned char> Eet::sha256(const std::string &str)
{
    std::vector<unsigned char> hash;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int len = 0;
    hash.resize(EVP_MD_size(EVP_sha256()));
    if(mdctx != nullptr)
    {
        if(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) == 1
           && EVP_DigestUpdate(mdctx, str.c_str(), str.size()) == 1
           && EVP_DigestFinal_ex(mdctx, &hash[0], &len) == 1)
        {
            hash.resize(len);
        }
        else
        {
            showDebug("Failed to compute SHA-256");
            hash.clear();
        }
        EVP_MD_CTX_free(mdctx);
    }
    return hash;
}

void Eet::showDebug(const std::string &text)
{
    (void)text;
#ifdef DEBUG
    if(text.empty()) return;
    std::cout << text;
    if(text.at(text.length()-1) != '\n') std::cout << std::endl;
#endif
}

std::string Eet::uuid4()
{
    char uuids[38];
    union
    {
        struct
        {
            uint32_t time_low;
            uint16_t time_mid;
            uint16_t time_hi_and_version;
            uint8_t  clk_seq_hi_res;
            uint8_t  clk_seq_low;
            uint8_t  node[6];
        };
        uint8_t __rnd[16];
    } uuid;
    int rc = RAND_bytes(uuid.__rnd, sizeof(uuid));
    if(!rc)
    {
        srand(time(nullptr));
        for(unsigned int i=0; i<sizeof(uuid); i++)
        {
            uuid.__rnd[i] = rand() % 256;
        }
    }
    // Refer Section 4.2 of RFC-4122 / RFC-9562
    // UUID verze 4, varianta 10xx (0x8-0xb) - vyžadováno XSD schématem EET 2.0 (UUIDType)
    uuid.clk_seq_hi_res = (uint8_t) ((uuid.clk_seq_hi_res & 0x3F) | 0x80);
    uuid.time_hi_and_version = (uint16_t) ((uuid.time_hi_and_version & 0x0FFF) | 0x4000);
    snprintf(uuids, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
            uuid.clk_seq_hi_res, uuid.clk_seq_low,
            uuid.node[0], uuid.node[1], uuid.node[2],
            uuid.node[3], uuid.node[4], uuid.node[5]);
    return std::string(uuids);
}

std::string Eet::base64Encode(std::vector<unsigned char> data)
{
    if(data.empty()) return "";
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, &data[0], (int)data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    std::string base64String(bufferPtr->data, bufferPtr->length);
    return base64String;
}

std::string Eet::formatCertificate()
{
    std::string cert(m_cert);
    int pos_start = cert.find_first_of('\n')+1;
    int pos_end   = cert.find("-----END CERTIFICATE-----", pos_start);
    cert = cert.substr(pos_start, pos_end - pos_start);
    cert.erase(std::remove(cert.begin(), cert.end(), '\n'), cert.end());
    return cert;
}

std::string Eet::formatBool(bool value)
{
    if(value) return "true";
    return "false";
}

std::string Eet::fillTemplate(const std::string &templ)
{
    std::stringstream ss;
    for(size_t i=0; i<templ.length(); ++i)
    {
        char c = templ.at(i);
        if(templ.substr(i,2) != "${" && templ.substr(i,3) != " @{")
        {
            ss << c;
            continue;
        }
        size_t p = templ.find_first_of('}',i+2);
        if(p == std::string::npos)
        {
            showDebug("Missing end of placeholder");
            ss << templ.substr(i);
            break;
        }
        bool attribute = c==' ';
        if(attribute)
            ++i; //skip space
        std::string name = templ.substr(i+2,p-i-2);
        StringIt it = m_values.find(name);
        if(it == m_values.end())
            showDebug(EetData::formatString("Unknown placeholder %s", templ.substr(i,p+1).c_str()));
        else
        {
            std::string value = it->second;
            if(!value.empty())
            {
                if(attribute)
                    value = EetData::formatString(" %s=\"%s\"", name.c_str(), value.c_str());
                ss << value;
            }
        }
        i = p;
    }
    return ss.str();
}

// Minimální čtení XML odpovědi bez externí knihovny. Stačí na strukturu odpovědi EET
// (Potvrzeni, Chyba, Varovani, případně SOAP Fault) - elementy se porovnávají podle
// jména bez prefixu jmenného prostoru, atributy mohou být v libovolném pořadí
// a v uvozovkách i apostrofech.
struct XmlElement
{
    std::string name;   // jméno bez prefixu (eet:Chyba -> Chyba)
    StringMap attrs;
    std::string text;   // text za počáteční značkou do další značky
};

static bool isXmlSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void appendUtf8(std::string &out, unsigned long cp)
{
    if(cp < 0x80)
    {
        out += (char)cp;
    }
    else if(cp < 0x800)
    {
        out += (char)(0xC0 | (cp >> 6));
        out += (char)(0x80 | (cp & 0x3F));
    }
    else if(cp < 0x10000)
    {
        out += (char)(0xE0 | (cp >> 12));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
    else
    {
        out += (char)(0xF0 | (cp >> 18));
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
}

// Převede entity (&lt; &gt; &amp; &quot; &apos; &#N; &#xN;), neznámé nechá beze změny
static std::string xmlUnescape(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for(size_t i=0; i<s.size(); ++i)
    {
        size_t semi;
        if(s[i] == '&' && (semi = s.find(';', i)) != std::string::npos && semi - i <= 10)
        {
            std::string ent = s.substr(i+1, semi-i-1);
            bool known = true;
            if(ent == "lt") out += '<';
            else if(ent == "gt") out += '>';
            else if(ent == "amp") out += '&';
            else if(ent == "quot") out += '"';
            else if(ent == "apos") out += '\'';
            else if(ent.size() > 1 && ent[0] == '#')
            {
                bool hex = ent[1] == 'x' || ent[1] == 'X';
                const char *digits = ent.c_str() + (hex ? 2 : 1);
                char *end = nullptr;
                unsigned long cp = 0;
                if(hex ? std::isxdigit((unsigned char)*digits) : std::isdigit((unsigned char)*digits))
                    cp = strtoul(digits, &end, hex ? 16 : 10);
                known = end && *end == '\0' && cp > 0 && cp < 0x110000;
                if(known) appendUtf8(out, cp);
            }
            else known = false;
            if(known)
            {
                i = semi;
                continue;
            }
        }
        out += s[i];
    }
    return out;
}

// Projde všechny počáteční značky v dokumentu. U neúplného XML skončí
// a vrátí elementy načtené do té doby.
static std::vector<XmlElement> parseXmlElements(const std::string &xml)
{
    std::vector<XmlElement> elements;
    const size_t n = xml.size();
    size_t i = 0;
    while((i = xml.find('<', i)) != std::string::npos)
    {
        if(xml.compare(i, 4, "<!--") == 0)
        {
            size_t end = xml.find("-->", i+4);
            if(end == std::string::npos) break;
            i = end + 3;
            continue;
        }
        if(i+1 < n && (xml[i+1] == '?' || xml[i+1] == '!' || xml[i+1] == '/'))
        {
            // XML deklarace, DOCTYPE, koncová značka
            size_t end = xml.find('>', i+1);
            if(end == std::string::npos) break;
            i = end + 1;
            continue;
        }
        XmlElement el;
        size_t p = i + 1;
        while(p < n && !isXmlSpace(xml[p]) && xml[p] != '>' && xml[p] != '/') ++p;
        std::string qname = xml.substr(i+1, p-i-1);
        size_t colon = qname.find(':');
        el.name = colon == std::string::npos ? qname : qname.substr(colon+1);
        bool closed = false;
        bool selfClosing = false;
        while(p < n)
        {
            while(p < n && isXmlSpace(xml[p])) ++p;
            if(p >= n) break;
            if(xml[p] == '>')
            {
                closed = true;
                ++p;
                break;
            }
            if(xml[p] == '/')
            {
                if(p+1 < n && xml[p+1] == '>')
                {
                    closed = selfClosing = true;
                    p += 2;
                }
                break;
            }
            size_t attrStart = p;
            while(p < n && !isXmlSpace(xml[p]) && xml[p] != '=' && xml[p] != '>' && xml[p] != '/') ++p;
            std::string attrName = xml.substr(attrStart, p-attrStart);
            while(p < n && isXmlSpace(xml[p])) ++p;
            if(p >= n || xml[p] != '=') break;
            ++p;
            while(p < n && isXmlSpace(xml[p])) ++p;
            if(p >= n || (xml[p] != '"' && xml[p] != '\'')) break;
            size_t valueEnd = xml.find(xml[p], p+1);
            if(valueEnd == std::string::npos) break;
            el.attrs[attrName] = xmlUnescape(xml.substr(p+1, valueEnd-p-1));
            p = valueEnd + 1;
        }
        if(!closed) break;
        if(!selfClosing)
        {
            size_t textEnd = xml.find('<', p);
            if(textEnd == std::string::npos) break;
            el.text = xmlUnescape(xml.substr(p, textEnd-p));
        }
        elements.push_back(el);
        i = p;
    }
    return elements;
}

static std::string xmlAttr(const XmlElement &el, const std::string &name)
{
    StringMap::const_iterator it = el.attrs.find(name);
    return it == el.attrs.end() ? std::string() : it->second;
}

void Eet::parseResponse(const std::string &response, OVERENI overeni)
{
    m_pok = "";
    m_chyba = "";
    m_varovani = "";
    bool overeno = false;
    std::string faultString;
    std::vector<XmlElement> elements = parseXmlElements(response);
    for(size_t i=0; i<elements.size(); ++i)
    {
        const XmlElement &el = elements[i];
        if(el.name == "Potvrzeni")
        {
            // Element Potvrzeni obsahuje atribut pok (POK) - viz PokType v EETXMLSchema.xsd
            m_pok = xmlAttr(el, "pok");
        }
        else if(el.name == "Chyba")
        {
            std::string kod = xmlAttr(el, "kod");
            // V ověřovacím módu značí úspěch chybový kód 0
            if(overeni == OVEROVACI && kod == "0")
                overeno = true;
            else
                m_chyba += "Kód: " + kod + "\n" + el.text + "\n";
        }
        else if(el.name == "Varovani")
        {
            m_varovani += "Kód: " + xmlAttr(el, "kod_varov") + "\n" + el.text + "\n";
        }
        else if(el.name == "faultstring")
        {
            faultString = el.text;
        }
    }
    if(overeno)
    {
        m_pok = "Overeno";
        m_chyba.clear();
        return;
    }
    if(m_pok.empty() && m_chyba.empty() && !faultString.empty())
    {
        m_chyba = "SOAP Fault: " + faultString + "\n";
    }
}

bool Eet::regexString20(const std::string &text)
{
    static const std::regex reg("[0-9a-zA-Z\\.,:;/#_ -]{1,20}");
    return std::regex_match(text, reg);
}

bool Eet::regexEic(const std::string &text)
{
    static const std::regex reg("CZ[0-9]{8,10}");
    if(!std::regex_match(text, reg)) return false;
    std::string cislo = text.substr(2);
    if(cislo.length() == 8 && !checkIcChecksum(cislo))
    {
        // Kontrolní součet lze ověřit pouze u EIČ ve tvaru CZ+IČO (8 číslic).
        // U EIČ odvozeného z rodného čísla nebo přiděleného VČP (9-10 číslic)
        // se kontrolní součet neověřuje.
        return false;
    }
    return true;
}

bool Eet::checkIcChecksum(const std::string &ic)
{
    // Kontrolní součet IČO (modulo 11, váhy 8-2), stejný algoritmus jako pro DIČ
    // právnických osob (DIČ = CZ + IČO). Neplatí pro EIČ odvozené z rodného čísla
    // nebo pro přidělené VČP.
    if(ic.length() != 8) return false;
    int soucet = 0;
    for(int i=0; i<7; i++)
    {
        soucet += (ic[i]-'0')*(8-i);
    }
    soucet %= 11;
    int c;
    if(soucet == 0 || soucet == 10) c = 1;
    else if(soucet == 1) c = 0;
    else c = 11 - soucet;
    return (ic[7]-'0') == c;
}

EetData::EetData()
{
    //Hlavicka - start
    m_datOdesl = formatTime(::time(nullptr));
    m_prvniZaslani = PRVNI;
    //Hlavicka - end
    //Data - start
    m_poradCis = "";
    m_datTrzby = formatTime(::time(nullptr));
    m_celkTrzba = "0.00";
    // Optional Data - start
    m_urcenoCerpZuct = "";
    m_cerpZuct = "";
    // Optional Data - end
    //Data - end
}

EetData::EetData(const std::string &poradCis, double celkTrzba, const ZASLANI &prvniZaslani, time_t datOdesl, time_t datTrzby,
                 double *urcenoCerpZuct, double *cerpZuct)
{
    //Hlavicka - start
    m_datOdesl = formatTime(datOdesl);
    m_prvniZaslani = prvniZaslani;
    //Hlavicka - end
    //Data - start
    m_poradCis = poradCis;
    m_datTrzby = formatTime(datTrzby);
    m_celkTrzba = formatDouble(celkTrzba);
    // Optional Data - start
    m_urcenoCerpZuct = urcenoCerpZuct?formatDouble(*urcenoCerpZuct):"";
    m_cerpZuct = cerpZuct?formatDouble(*cerpZuct):"";
    // Optional Data - end
    //Data - end
}

EETCODE EetData::checkData()
{
    //Hlavicka - start
    if(!regexTime(m_datOdesl))
    {
        m_chyba = "Chyba v Datum a čas odeslání zprávy";
        return EET_ERROR;
    }
    if(m_prvniZaslani<OPAKOVANE || m_prvniZaslani>PRVNI)
    {
        m_chyba = "Chyba v První zaslání údajů o tržbě";
        return EET_ERROR;
    }
    //Hlavicka - end
    //Data - start
    if(!regexString25(m_poradCis))
    {
        m_chyba = "Chyba v Pořadové číslo účtenky";
        return EET_ERROR;
    }
    if(!regexTime(m_datTrzby))
    {
        m_chyba = "Chyba v Datum a čas přijetí tržby";
        return EET_ERROR;
    }
    if(!regexDouble(m_celkTrzba))
    {
        m_chyba = "Chyba v Celková částka tržby";
        return EET_ERROR;
    }
    // Optional Data - start
    if(!m_urcenoCerpZuct.empty() && !regexDouble(m_urcenoCerpZuct))
    {
        m_chyba = "Chyba v Celková částka plateb určená k následnému čerpání nebo zúčtování";
        return EET_ERROR;
    }
    if(!m_cerpZuct.empty() && !regexDouble(m_cerpZuct))
    {
        m_chyba = "Chyba v Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby";
        return EET_ERROR;
    }
    // Optional Data - end
    //Data - end
    return EET_OK;
}

std::string EetData::formatString(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    if (n <= 0)
        return std::string();

    std::string str(n, '\0');
    va_start(ap, fmt);
    vsnprintf(str.data(), n + 1, fmt, ap);
    va_end(ap);
    return str;
}

std::string EetData::formatDouble(double val)
{
    std::ostringstream convert;
    convert.imbue(std::locale::classic());
    double roundedVal = std::round(val * 100.0) / 100.0;
    if (roundedVal == 0.0) roundedVal = 0.0;
    convert << std::fixed << std::setprecision(2) << roundedVal;
    return convert.str();
}

bool EetData::regexDouble(const std::string &text)
{
    static const std::regex reg("((0|-?[1-9]\\d{0,7})\\.\\d\\d|-0\\.(0[1-9]|[1-9]\\d))");
    return std::regex_match(text, reg);
}

static void localTime(time_t time, struct tm *out)
{
#ifdef _WIN32
    localtime_s(out, &time);
#else
    localtime_r(&time, out);
#endif
}

static void utcTime(time_t time, struct tm *out)
{
#ifdef _WIN32
    gmtime_s(out, &time);
#else
    gmtime_r(&time, out);
#endif
}

std::string EetData::formatTime(time_t time)
{
    struct tm localTm;
    localTime(time, &localTm);
    char buffer[512];
    int len = strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &localTm);
    std::string s(buffer, len);
    struct tm utcTm;
    utcTime(time, &utcTm);
    utcTm.tm_isdst = localTm.tm_isdst;
    time_t utcAsLocalDst = mktime(&utcTm);
    long gmtoffSeconds = (long)difftime(time, utcAsLocalDst);
    int gmtoffHours = (int)(gmtoffSeconds / 3600);

    return formatString("%s%c%02d:00", s.c_str(), gmtoffHours>=0?'+':'-', std::abs(gmtoffHours));
}

bool EetData::regexTime(const std::string &text)
{
    static const std::regex reg("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(Z|[+\\-]\\d\\d:\\d\\d)");
    return std::regex_match(text, reg);
}

bool EetData::regexString25(const std::string &text)
{
    static const std::regex reg("[0-9a-zA-Z\\.,:;/#_ -]{1,25}");
    return std::regex_match(text, reg);
}

std::string EetData::getChyba()
{
    return m_chyba;
}

std::string EetData::getDatOdesl() const
{
    return m_datOdesl;
}

EETCODE EetData::setDatOdesl(const std::string &datOdesl)
{
    if(!regexTime(datOdesl))
    {
        m_chyba = "Chyba v Datum a čas odeslání zprávy";
        return EET_ERROR;
    }
    m_datOdesl = datOdesl;
    return EET_OK;
}

EETCODE EetData::setDatOdesl(time_t datOdesl)
{
    m_datOdesl = formatTime(datOdesl);
    return EET_OK;
}

ZASLANI EetData::getPrvniZaslani() const
{
    return m_prvniZaslani;
}

EETCODE EetData::setPrvniZaslani(const ZASLANI &prvniZaslani)
{
    if(prvniZaslani<OPAKOVANE || prvniZaslani>PRVNI)
    {
        m_chyba = "Chyba v První zaslání údajů o tržbě";
        return EET_ERROR;
    }
    m_prvniZaslani = prvniZaslani;
    return EET_OK;
}

std::string EetData::getPoradCis() const
{
    return m_poradCis;
}

EETCODE EetData::setPoradCis(const std::string &poradCis)
{
    if(!regexString25(poradCis))
    {
        m_chyba = "Chyba v Pořadové číslo účtenky";
        return EET_ERROR;
    }
    m_poradCis = poradCis;
    return EET_OK;
}

std::string EetData::getDatTrzby() const
{
    return m_datTrzby;
}

EETCODE EetData::setDatTrzby(const std::string &datTrzby)
{
    if(!regexTime(datTrzby))
    {
        m_chyba = "Chyba v Datum a čas přijetí tržby";
        return EET_ERROR;
    }
    m_datTrzby = datTrzby;
    return EET_OK;
}

EETCODE EetData::setDatTrzby(time_t datTrzby)
{
    m_datTrzby = formatTime(datTrzby);
    return EET_OK;
}

std::string EetData::getCelkTrzba() const
{
    return m_celkTrzba;
}

EETCODE EetData::setCelkTrzba(const std::string &celkTrzba)
{
    if(!regexDouble(celkTrzba))
    {
        m_chyba = "Chyba v Celková částka tržby";
        return EET_ERROR;
    }
    m_celkTrzba = celkTrzba;
    return EET_OK;
}

EETCODE EetData::setCelkTrzba(double celkTrzba)
{
    m_celkTrzba = formatDouble(celkTrzba);
    if(!regexDouble(m_celkTrzba))
    {
        m_chyba = "Chyba v Celková částka tržby";
        m_celkTrzba = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getUrcenoCerpZuct() const
{
    return m_urcenoCerpZuct;
}

EETCODE EetData::setUrcenoCerpZuct(const std::string &urcenoCerpZuct)
{
    if(!regexDouble(urcenoCerpZuct))
    {
        m_chyba = "Chyba v Celková částka plateb určená k následnému čerpání nebo zúčtování";
        return EET_ERROR;
    }
    m_urcenoCerpZuct = urcenoCerpZuct;
    return EET_OK;
}

EETCODE EetData::setUrcenoCerpZuct(double urcenoCerpZuct)
{
    m_urcenoCerpZuct = formatDouble(urcenoCerpZuct);
    if(!regexDouble(m_urcenoCerpZuct))
    {
        m_chyba = "Chyba v Celková částka plateb určená k následnému čerpání nebo zúčtování";
        m_urcenoCerpZuct = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getCerpZuct() const
{
    return m_cerpZuct;
}

EETCODE EetData::setCerpZuct(const std::string &cerpZuct)
{
    if(!regexDouble(cerpZuct))
    {
        m_chyba = "Chyba v Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby";
        return EET_ERROR;
    }
    m_cerpZuct = cerpZuct;
    return EET_OK;
}

EETCODE EetData::setCerpZuct(double cerpZuct)
{
    m_cerpZuct = formatDouble(cerpZuct);
    if(!regexDouble(m_cerpZuct))
    {
        m_chyba = "Chyba v Celková částka plateb, které jsou následným čerpáním nebo zúčtováním platby";
        m_cerpZuct = "";
        return EET_ERROR;
    }
    return EET_OK;
}
