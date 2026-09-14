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

#if _MSC_VER
    #define VSNPRINTF _vsnprintf
    #if _MSC_VER < 1900
    #define snprintf c99_snprintf
    #define vsnprintf c99_vsnprintf
    __inline int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap)
    {
        int count = -1;
        if (size != 0)
            count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
        if (count == -1)
            count = _vscprintf(format, ap);
        return count;
    }

    __inline int c99_snprintf(char *outBuf, size_t size, const char *format, ...)
    {
        int count;
        va_list ap;
        va_start(ap, format);
        count = c99_vsnprintf(outBuf, size, format, ap);
        va_end(ap);
        return count;
    }
    #endif
#else
    #define VSNPRINTF vsnprintf
#endif

static size_t curlCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

Eet::Eet()
    : m_overeni(PRODUKCNI), m_eicPopl(""), m_eicPoverujiciho(""), m_povereniVicePopl(false), m_idJednotky(0), m_idPokl(""), m_certPath(""), m_pass(""), m_key(NULL), m_cert(NULL),
      m_playground(true)
{
}

Eet::Eet(const std::string &eicPopl, int idJednotky, const std::string &cert, const std::string &pass, const std::string &idPokl, const std::string &eicPoverujiciho,
         const OVERENI &overeni, bool playground)
    : m_overeni(overeni), m_eicPopl(eicPopl), m_eicPoverujiciho(eicPoverujiciho), m_povereniVicePopl(false), m_idJednotky(idJednotky), m_idPokl(idPokl), m_certPath(cert), m_pass(pass),
      m_playground(playground)
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
    if(m_cert == NULL || m_key == NULL)
    {
        m_chyba = "Chyba certifikátu";
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
    CURL *curl;
    CURLcode res = CURLE_OK;
    struct curl_slist *headers = NULL;
    curl = curl_easy_init();
    if(curl)
    {
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
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    if(res == CURLE_OK)
    {
        showDebug("Response:");
        showDebug(response);
        parseResponse(response, m_overeni);
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
    }
    else
    {
        m_chyba = curl_easy_strerror(res);
        return EET_ERROR;
    }
    m_chyba.clear();
    m_varovani.clear();
    return EET_OK;
}

bool Eet::createKeyCert()
{
    m_key = NULL;
    m_cert = NULL;
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Řada reálných produkčních .p12 certifikátů (např. od Finanční správy) je
    // zašifrována starším algoritmem RC2-40-CBC. OpenSSL 3.0 tyto algoritmy
    // přesunulo do tzv. "legacy" provideru, který se defaultně nenačítá - bez
    // něj parsování takového PKCS#12 souboru selže s chybou "unsupported".
    static bool providersLoaded = false;
    if(!providersLoaded)
    {
        if(OSSL_PROVIDER_load(NULL, "legacy") == NULL)
        {
            showDebug("Nepodařilo se načíst OpenSSL legacy provider (starší RC2/3DES šifrování v PKCS#12 nemusí fungovat)");
        }
        if(OSSL_PROVIDER_load(NULL, "default") == NULL)
        {
            showDebug("Nepodařilo se načíst OpenSSL default provider");
        }
        providersLoaded = true;
    }
#endif

    #ifndef _WIN32
        fp = fopen(m_certPath.c_str(), "rb");
    #else
        // On Windows, non-ascii characters in path don't work with fopen(). Thus use _wfopen() instead.
        std::wstring filePathW;
        filePathW.resize(m_certPath.size());
        int newSize = MultiByteToWideChar(CP_UTF8, 0, m_certPath.c_str(), m_certPath.length(), const_cast<wchar_t *>(filePathW.c_str()), m_certPath.length());
        filePathW.resize(newSize);
        fp = _wfopen(filePathW.c_str(), L"rb");
    #endif

    if(!fp)
    {
        m_chyba = EetData::formatString("Chyba při otevírání souboru certifikátu %s", m_certPath.c_str());
        showDebug(m_chyba);
        return false;
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if(!p12)
    {
        m_chyba = "Chyba při čtení PKCS#12 souboru";
        showDebug(m_chyba);
        ERR_print_errors_fp(stderr);
        return false;
    }
    if(!PKCS12_parse(p12, m_pass.c_str(), &pkey, &cert, &ca))
    {
        m_chyba = "Chyba při parsování PKCS#12 souboru";
        showDebug(m_chyba);
        ERR_print_errors_fp(stderr);
        return false;
    }
    PKCS12_free(p12);
    if(pkey)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
        m_key = (char *)malloc(BIO_number_written(bio) + 1);
        memset(m_key, 0, BIO_number_written(bio) + 1);
        BIO_read(bio, m_key, BIO_number_written(bio));
        BIO_free(bio);
    }
    if(cert)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, cert);
        m_cert = (char *)malloc(BIO_number_written(bio) + 1);
        memset(m_cert, 0, BIO_number_written(bio) + 1);
        BIO_read(bio, m_cert, BIO_number_written(bio));
        BIO_free(bio);
    }
    sk_X509_pop_free(ca, X509_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return m_key!=NULL && m_cert!=NULL;
}

EVP_PKEY *Eet::createPKey(bool pub)
{
    EVP_PKEY *pkey = NULL;
    if(pub)
    {
        BIO *keybio = BIO_new_mem_buf(m_cert, -1);
        if(keybio==NULL)
        {
            showDebug("Failed to create key BIO");
            return NULL;
        }
        pkey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
        BIO_free(keybio);
    }
    else
    {
        BIO *keybio = BIO_new_mem_buf(m_key, -1);
        if(keybio==NULL)
        {
            showDebug("Failed to create key BIO");
            return NULL;
        }
        pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
        BIO_free(keybio);
    }
    if(pkey == NULL)
    {
        showDebug("Failed to create EVP_PKEY");
    }
    return pkey;
}

std::vector<unsigned char> Eet::createSignature(const std::string &plaintext)
{
    std::vector<unsigned char> signature;
    EVP_PKEY *pkey = createPKey(false);
    if(pkey == NULL) return signature;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL)
    {
        showDebug("Failed to create EVP_MD_CTX");
        EVP_PKEY_free(pkey);
        return signature;
    }

    const unsigned char *tbs = (const unsigned char *)plaintext.c_str();
    size_t tbslen = plaintext.size();
    size_t siglen = 0;
    bool ok = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1
              && EVP_DigestSign(mdctx, NULL, &siglen, tbs, tbslen) == 1;

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
    EVP_PKEY_free(pkey);
    return signature;
}

std::vector<unsigned char> Eet::sha256(const std::string &str)
{
    std::vector<unsigned char> hash;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int len = 0;
    hash.resize(EVP_MD_size(EVP_sha256()));
    if(mdctx != NULL)
    {
        if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1
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
        srand(time(NULL));
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

std::string Eet::byte2Hex(std::vector<unsigned char> data)
{
    std::stringstream ss;
    for(size_t i = 0; i < data.size(); ++i)
    {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
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
            showDebug("Missing end of placeholder");
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

void Eet::parseResponse(const std::string &response, OVERENI overeni)
{
    m_pok = "";
    m_chyba = "";
    m_varovani = "";
    size_t pos1, pos2;
    if(overeni == OVEROVACI)
    {
        // V ověřovacím módu značí úspěch chybový kód 0 (element Chyba, kod="0")
        if(response.find("Chyba kod=\"0\"") != std::string::npos)
        {
            m_pok = "Overeno";
            //response obsahuje Varovani
            if(response.find(":Varovani") != std::string::npos || response.find("<Varovani") != std::string::npos)
            {
                size_t start = response.find("Varovani");
                for(size_t i=start; i<response.length(); ++i)
                {
                    if(response.substr(i,10) == "kod_varov=")
                    {
                        pos1 = response.find('"', i);
                        pos2 = response.find('"', pos1+1);
                        m_varovani.append("Kód: ");
                        m_varovani.append(response.substr(pos1+1, pos2-pos1-1));
                        m_varovani.append("\n");
                        pos1 = response.find('>', pos2);
                        pos2 = response.find('<', pos1+1);
                        m_varovani.append(response.substr(pos1+1, pos2-pos1-1));
                        m_varovani.append("\n");
                        i = pos2;
                    }
                }
            }
            return;
        }
    }
    // Element Potvrzeni obsahuje atribut pok (POK) - viz PokType v EETXMLSchema.xsd
    size_t pok = response.find("Potvrzeni ");
    if(pok != std::string::npos)
    {
        size_t attr = response.find("pok=", pok);
        size_t elementEnd = response.find('>', pok);
        if(attr != std::string::npos && (elementEnd == std::string::npos || attr < elementEnd))
        {
            pos1 = response.find('"', attr);
            pos2 = response.find('"', pos1+1);
            m_pok = response.substr(pos1+1, pos2-pos1-1);
        }
    }
    //response obsahuje Varovani
    if(response.find(":Varovani") != std::string::npos || response.find("<Varovani") != std::string::npos)
    {
        for(size_t i=response.find("Varovani"); i<response.length(); ++i)
        {
            if(response.substr(i,10) == "kod_varov=")
            {
                pos1 = response.find('"', i);
                pos2 = response.find('"', pos1+1);
                m_varovani.append("Kód: ");
                m_varovani.append(response.substr(pos1+1, pos2-pos1-1));
                m_varovani.append("\n");
                pos1 = response.find('>', pos2);
                pos2 = response.find('<', pos1+1);
                m_varovani.append(response.substr(pos1+1, pos2-pos1-1));
                m_varovani.append("\n");
                i = pos2;
            }
        }
    }
    //response obsahuje Chyba
    if(response.find("Chyba") != std::string::npos)
    {
        for(size_t i=response.find("Chyba"); i<response.length(); ++i)
        {
            if(response.substr(i,4) == "kod=")
            {
                pos1 = response.find('"', i);
                pos2 = response.find('"', pos1+1);
                m_chyba.append("Kód: ");
                m_chyba.append(response.substr(pos1+1, pos2-pos1-1));
                m_chyba.append("\n");
                pos1 = response.find('>', pos2);
                pos2 = response.find('<', pos1+1);
                m_chyba.append(response.substr(pos1+1, pos2-pos1-1));
                m_chyba.append("\n");
                i = pos2;
            }
        }
    }
}

bool Eet::regexString20(const std::string &text)
{
    std::regex reg("[0-9a-zA-Z\\.,:;/#_ -]{1,20}");
    return std::regex_match(text, reg);
}

bool Eet::regexEic(const std::string &text)
{
    std::regex reg("CZ[0-9]{8,10}");
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
    m_datOdesl = formatTime(::time(NULL));
    m_prvniZaslani = PRVNI;
    //Hlavicka - end
    //Data - start
    m_poradCis = "";
    m_datTrzby = formatTime(::time(NULL));
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
    std::vector<char> str(100,'\0');
    va_list ap;
    while(1)
    {
        va_start(ap, fmt);
        int n = VSNPRINTF(str.data(), str.size(), fmt, ap);
        va_end(ap);
        if((n > -1) && (size_t(n) < str.size()))
        {
            return str.data();
        }
        if(n > -1)
            str.resize(n + 1);
        else
            str.resize(str.size() * 2);
    }
    return str.data();
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
    std::regex reg("((0|-?[1-9]\\d{0,7})\\.\\d\\d|-0\\.(0[1-9]|[1-9]\\d))");
    return std::regex_match(text, reg);
}

std::string EetData::formatTime(time_t time)
{
    struct tm localTm = *localtime(&time);
    char buffer[512];
    int len = strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &localTm);
    std::string s(buffer, len);
    struct tm utcTm = *gmtime(&time);
    utcTm.tm_isdst = localTm.tm_isdst;
    time_t utcAsLocalDst = mktime(&utcTm);
    long gmtoffSeconds = (long)difftime(time, utcAsLocalDst);
    int gmtoffHours = (int)(gmtoffSeconds / 3600);

    return formatString("%s%c%02d:00", s.c_str(), gmtoffHours>=0?'+':'-', std::abs(gmtoffHours));
}

bool EetData::regexTime(const std::string &text)
{
    std::regex reg("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(Z|[+\\-]\\d\\d:\\d\\d)");
    return std::regex_match(text, reg);
}

bool EetData::regexString25(const std::string &text)
{
    std::regex reg("[0-9a-zA-Z\\.,:;/#_ -]{1,25}");
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
