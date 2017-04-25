/***************************************************************
 * Name:      eet.cpp
 * Author:    David Vachulka (arch_dvx@users.sourceforge.net)
 * Copyright: 2016
 * License:   LGPL3
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
#include <regex>
#include <locale>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <curl/curl.h>

#if _MSC_VER
    #define VSNPRINTF _vsnprintf
#else
    #define VSNPRINTF vsnprintf
#endif

class tecka : public std::numpunct<char>
{
    protected:
        char do_decimal_point() const { return '.'; }
};

static size_t curlCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

Eet::Eet()
    : m_overeni(PRODUKCNI), m_dicPopl(""), m_dicPoverujiciho(""), m_idProvoz(0), m_idPokl(""), m_rezim(STANDARDNI), m_certPath(""), m_pass(""),
      m_playground(true)
{
}

Eet::Eet(const std::string &dicPopl, int idProvoz, const std::string &cert, const std::string &pass, const std::string &idPokl, const std::string &dicPoverujiciho,
         const OVERENI &overeni, const REZIM &rezim, bool playground)
    : m_overeni(overeni), m_dicPopl(dicPopl), m_dicPoverujiciho(dicPoverujiciho), m_idProvoz(idProvoz), m_idPokl(idPokl), m_rezim(rezim), m_certPath(cert), m_pass(pass),
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

EETCODE Eet::setDicPopl(const std::string &dicPopl)
{
    if(!regexDic(dicPopl))
    {
        m_chyba = "Chyba v DIČ poplatníka";
        return EET_ERROR;
    }
    m_dicPopl = dicPopl;
    return EET_OK;
}

EETCODE Eet::setDicPoverujiciho(const std::string &dicPoverujiciho)
{
    if(dicPoverujiciho.empty())
    {
        m_dicPoverujiciho = "";
        return EET_OK;
    }
    if(!regexDic(dicPoverujiciho))
    {
        m_chyba = "Chyba v DIČ pověřujícího poplatníka";
        return EET_ERROR;
    }
    m_dicPoverujiciho = dicPoverujiciho;
    return EET_OK;
}

EETCODE Eet::setIdProvoz(int idProvoz)
{
    if(idProvoz<1 || idProvoz>999999)
    {
        m_chyba = "Chyba v Označení provozovny";
        return EET_ERROR;
    }
    m_idProvoz = idProvoz;
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

std::string Eet::getPkp()
{
    return formatPkp();
}

std::string Eet::getBkp()
{
    return formatBkp();
}

std::string Eet::getFik()
{
    return m_fik;
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

    if(data.checkData() != EET_OK)
    {
        m_chyba = data.getChyba();
        return EET_ERROR;
    }

    std::stringstream ss;
    ss << m_dicPopl << "|" << m_idProvoz << "|" << m_idPokl << "|" << data.getPoradCis() << "|" << data.getDatTrzby() << "|" << data.getCelkTrzba();
    createPkpBkp(ss.str());

    m_values.clear();
    m_values.insert(StringPair("prvni_zaslani", formatBool(data.getPrvniZaslani())));
    m_values.insert(StringPair("dat_odesl", data.getDatOdesl()));
    m_values.insert(StringPair("uuid_zpravy", uuid4()));
    m_values.insert(StringPair("overeni", formatBool(m_overeni)));
    m_values.insert(StringPair("certb64", formatCertificate()));
    m_values.insert(StringPair("dic_popl", m_dicPopl));
    m_values.insert(StringPair("dic_poverujiciho", m_dicPoverujiciho));
    m_values.insert(StringPair("id_provoz", EetData::formatString("%d", m_idProvoz)));
    m_values.insert(StringPair("id_pokl", m_idPokl));
    m_values.insert(StringPair("porad_cis", data.getPoradCis()));
    m_values.insert(StringPair("dat_trzby", data.getDatTrzby()));
    m_values.insert(StringPair("celk_trzba", data.getCelkTrzba()));
    m_values.insert(StringPair("zakl_nepodl_dph", data.getZaklNepodlDph()));
    m_values.insert(StringPair("zakl_dan1", data.getZaklDan1()));
    m_values.insert(StringPair("dan1", data.getDan1()));
    m_values.insert(StringPair("zakl_dan2", data.getZaklDan2()));
    m_values.insert(StringPair("dan2", data.getDan2()));
    m_values.insert(StringPair("zakl_dan3", data.getZaklDan3()));
    m_values.insert(StringPair("dan3", data.getDan3()));
    m_values.insert(StringPair("cest_sluz", data.getCestSluz()));
    m_values.insert(StringPair("pouzit_zboz1", data.getPouzitZboz1()));
    m_values.insert(StringPair("pouzit_zboz2", data.getPouzitZboz2()));
    m_values.insert(StringPair("pouzit_zboz3", data.getPouzitZboz3()));
    m_values.insert(StringPair("urceno_cerp_zuct", data.getUrcenoCerpZuct()));
    m_values.insert(StringPair("cerp_zuct", data.getCerpZuct()));
    m_values.insert(StringPair("rezim", EetData::formatString("%d", m_rezim)));
    m_values.insert(StringPair("bkp", formatBkp()));
    m_values.insert(StringPair("pkp", formatPkp()));

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
    CURLcode res;
    curl = curl_easy_init();
    if(curl)
    {
        curl_easy_setopt(curl, CURLOPT_HEADER, "SOAPACTION: http://fs.mfcr.cz/eet/OdeslaniTrzby");
        curl_easy_setopt(curl, CURLOPT_HEADER, "Content-Type: text/xml;charset=UTF-8");
        curl_easy_setopt(curl, CURLOPT_URL, m_playground?PGURL:PRODUKCNIURL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, templateRequest.c_str());
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_1);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    if(res == CURLE_OK)
    {
        showDebug("Response:");
        showDebug(response);
        parseResponse(response, m_overeni);
        if(m_overeni == OVEROVACI && !m_fik.empty())
        {
            m_fik.clear();
            if(!m_varovani.empty()) return EET_VAROVANI;
            else return EET_OVERENO;
        }
        if(!m_chyba.empty()) return EET_CHYBA;
        if(!m_varovani.empty()) return EET_VAROVANI;
        if(m_fik.empty())
        {
            m_chyba = "Nepodařilo se získat FIK";
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
    if(!(fp = fopen(m_certPath.c_str(), "rb")))
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
        BIO *bio = NULL;
        bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
        m_key = (char *)malloc(bio->num_write + 1);
        memset(m_key, 0, bio->num_write + 1);
        BIO_read(bio, m_key, bio->num_write);
        BIO_free(bio);
    }
    if(cert)
    {
        BIO *bio = NULL;
        bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, cert);
        m_cert = (char *)malloc(bio->num_write + 1);
        memset(m_cert, 0, bio->num_write + 1);
        BIO_read(bio, m_cert, bio->num_write);
        BIO_free(bio);
    }
    sk_X509_pop_free(ca, X509_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return m_key!=NULL && m_cert!=NULL;
}

RSA *Eet::createRSA(bool pub)
{
    RSA *rsa= NULL;
    if(pub)
    {
        BIO *keybio;
        keybio = BIO_new_mem_buf(m_cert, -1);
        if(keybio==NULL)
        {
            showDebug("Failed to create key BIO");
            return NULL;
        }
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        BIO *keybio;
        keybio = BIO_new_mem_buf(m_key, -1);
        if(keybio==NULL)
        {
            showDebug("Failed to create key BIO");
            return NULL;
        }
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
    {
        showDebug("Failed to create RSA");
    }
    return rsa;
}

void Eet::createPkpBkp(const std::string &plaintext)
{
    m_pkp.clear();
    m_bkp.clear();
    std::vector<unsigned char> hash256 = sha256(plaintext);
    showDebug(EetData::formatString("Plaintext\n%s\n", plaintext.c_str()));
    showDebug(EetData::formatString("Hash\n%s\n", byte2Hex(hash256).c_str()));
    if(!m_key) return;
    if(!createPkp(hash256)) return;
    showDebug(EetData::formatString("PKP\n%s\n", formatPkp().c_str()));
    m_bkp = sha1(m_pkp);
    showDebug(EetData::formatString("BKP\n%s\n", formatBkp().c_str()));
}

bool Eet::createPkp(std::vector<unsigned char> data)
{
    RSA *rsa = createRSA(false);
    if(rsa == NULL) return false;
    std::vector<unsigned char> block(RSA_size(rsa));
    unsigned int siglen;
    int ret = RSA_sign(NID_sha256, &data[0], data.size(), &block[0], &siglen, rsa);
    if(ret) m_pkp = block;
    return ret;
}

std::vector<unsigned char> Eet::createSignature(const std::string &plaintext)
{
    RSA *rsa = createRSA(false);
    std::vector<unsigned char> block;
    if(rsa == NULL) return block;
    std::vector<unsigned char> hash = sha256(plaintext);
    block.resize(RSA_size(rsa));
    unsigned int siglen;
    int ret = RSA_sign(NID_sha256, &hash[0], hash.size(), &block[0], &siglen, rsa);
    if(!ret) showDebug("Neco se podelalo");
    return block;
}

std::vector<unsigned char> Eet::sha1(std::vector<unsigned char> data)
{
    std::vector<unsigned char> hash;
    hash.resize(20);
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, &data[0], data.size());
    SHA1_Final(&hash[0], &sha1);
    return hash;
}

std::vector<unsigned char> Eet::sha256(const std::string &str)
{
    std::vector<unsigned char> hash;
    hash.resize(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(&hash[0], &sha256);
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
    // Refer Section 4.2 of RFC-4122
    // https://tools.ietf.org/html/rfc4122#section-4.2
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
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

std::string Eet::formatPkp()
{
    if(m_pkp.empty()) return "";
    return base64Encode(m_pkp);
}

std::string Eet::formatBkp()
{
    if(m_bkp.empty()) return "";
    std::string res = byte2Hex(m_bkp);
    if(res.length() < 40) return "";
    res.insert(8,1,'-');
    res.insert(17,1,'-');
    res.insert(26,1,'-');
    res.insert(35,1,'-');
    return res;
}

std::string Eet::formatCertificate()
{
    std::string cert(m_cert);
    cert = cert.substr(cert.find_first_of('\n')+1, cert.find_last_of("==")-cert.find_first_of('\n')+1);
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
    m_fik = "";
    m_chyba = "";
    m_varovani = "";
    if(overeni == OVEROVACI)
    {
        if(response.find("eet:Chyba kod=\"0\"") != std::string::npos)
        {
            m_fik = "Overeno";
            //response obsahuje Varovani
            if(response.find("<eet:Varovani") != std::string::npos)
            {
                size_t pos1, pos2;
                for(size_t i=response.find("<eet:Varovani"); i<response.length(); ++i)
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
    size_t fik = response.find("Potvrzeni fik");
    size_t pos1, pos2;
    if(fik != std::string::npos)
    {
        pos1 = response.find('"', fik);
        pos2 = response.find('"', pos1+1);
        m_fik = response.substr(pos1+1, pos2-pos1-1);
    }
    //response obsahuje Varovani
    if(response.find("<eet:Varovani") != std::string::npos)
    {
        for(size_t i=response.find("<eet:Varovani"); i<response.length(); ++i)
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
    if(response.find("<eet:Chyba") != std::string::npos)
    {
        for(size_t i=response.find("<eet:Chyba"); i<response.length(); ++i)
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

bool Eet::regexDic(const std::string &text)
{
    std::regex reg("CZ[0-9]{8,10}");
    return std::regex_match(text, reg);
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
    m_rezim = STANDARDNI;
    // Optional Data - start
    m_zaklNepodlDph = "";
    m_zaklDan1 = "";
    m_dan1 = "";
    m_zaklDan2 = "";
    m_dan2 = "";
    m_zaklDan3 = "";
    m_dan3 = "";
    m_cestSluz = "";
    m_pouzitZboz1 = "";
    m_pouzitZboz2 = "";
    m_pouzitZboz3 = "";
    m_urcenoCerpZuct = "";
    m_cerpZuct = "";
    // Optional Data - end
    //Data - end
}

EetData::EetData(const std::string &poradCis, double celkTrzba, double *zaklNepodlDph, double *zaklDan1, double *dan1, double *zaklDan2, double *dan2, double *zaklDan3, double *dan3,
                 const ZASLANI &prvniZaslani, const REZIM &rezim, time_t datOdesl, time_t datTrzby, double *cestSluz, double *pouzitZboz1, double *pouzitZboz2, double *pouzitZboz3,
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
    m_rezim = rezim;
    // Optional Data - start
    m_zaklNepodlDph = zaklNepodlDph?formatDouble(*zaklNepodlDph):"";
    m_zaklDan1 = zaklDan1?formatDouble(*zaklDan1):"";
    m_dan1 = dan1?formatDouble(*dan1):"";
    m_zaklDan2 = zaklDan2?formatDouble(*zaklDan2):"";
    m_dan2 = dan2?formatDouble(*dan2):"";
    m_zaklDan3 = zaklDan3?formatDouble(*zaklDan3):"";
    m_dan3 = dan3?formatDouble(*dan3):"";
    m_cestSluz = cestSluz?formatDouble(*cestSluz):"";
    m_pouzitZboz1 = pouzitZboz1?formatDouble(*pouzitZboz1):"";
    m_pouzitZboz2 = pouzitZboz2?formatDouble(*pouzitZboz2):"";
    m_pouzitZboz3 = pouzitZboz3?formatDouble(*pouzitZboz3):"";
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
    if(m_rezim<STANDARDNI || m_rezim>ZJEDNODUSENY)
    {
        m_chyba = "Chyba v Režim tržby";
        return EET_ERROR;
    }
    // Optional Data - start
    if(!m_zaklNepodlDph.empty() && !regexDouble(m_zaklNepodlDph))
    {
        m_chyba = "Chyba v Celková částka plnění osvobozených od DPH, ostatních plnění";
        return EET_ERROR;
    }
    if(!m_zaklDan1.empty() && !regexDouble(m_zaklDan1))
    {
        m_chyba = "Chyba v Celkový základ daně se základní sazbou DPH";
        return EET_ERROR;
    }
    if(!m_dan1.empty() && !regexDouble(m_dan1))
    {
        m_chyba = "Chyba v Celková DPH se základní sazbou";
        return EET_ERROR;
    }
    if(!m_zaklDan2.empty() && !regexDouble(m_zaklDan2))
    {
        m_chyba = "Chyba v Celkový základ daně s první sníženou sazbou DPH";
        return EET_ERROR;
    }
    if(!m_dan2.empty() && !regexDouble(m_dan2))
    {
        m_chyba = "Chyba v Celková DPH s první sníženou sazbou";
        return EET_ERROR;
    }
    if(!m_zaklDan3.empty() && !regexDouble(m_zaklDan3))
    {
        m_chyba = "Chyba v Celkový základ daně s druhou sníženou sazbou DPH";
        return EET_ERROR;
    }
    if(!m_dan3.empty() && !regexDouble(m_dan3))
    {
        m_chyba = "Chyba v Celková DPH s druhou sníženou sazbou";
        return EET_ERROR;
    }
    if(!m_cestSluz.empty() && !regexDouble(m_cestSluz))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro cestovní službu";
        return EET_ERROR;
    }
    if(!m_pouzitZboz1.empty() && !regexDouble(m_pouzitZboz1))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou";
        return EET_ERROR;
    }
    if(!m_pouzitZboz2.empty() && !regexDouble(m_pouzitZboz2))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou";
        return EET_ERROR;
    }
    if(!m_pouzitZboz3.empty() && !regexDouble(m_pouzitZboz3))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou";
        return EET_ERROR;
    }
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
    std::locale eetlocale(std::locale(), new tecka);
    convert.imbue(eetlocale);
    convert << std::fixed << std::setprecision(2) << val;
    return convert.str();
}

bool EetData::regexDouble(const std::string &text)
{
    std::regex reg("((0|-?[1-9]\\d{0,7})\\.\\d\\d|-0\\.(0[1-9]|[1-9]\\d))");
    return std::regex_match(text, reg);
}

std::string EetData::formatTime(time_t time)
{
    struct tm *timeinfo = localtime(&time);
    char buffer[512];
    int len = strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);
    std::string s(buffer, len);
    int gmtoff;
#if __WIN32__
    gmtoff = -(timezone - (timeinfo->tm_isdst>0?3600:0))/3600;
#else
    gmtoff = timeinfo->tm_gmtoff/3600;
#endif
    return formatString("%s+0%d:00", s.c_str(), gmtoff);
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

REZIM EetData::getRezim() const
{
    return m_rezim;
}

EETCODE EetData::setRezim(const REZIM &rezim)
{
    if(rezim<STANDARDNI || rezim>ZJEDNODUSENY)
    {
        m_chyba = "Chyba v Režim tržby";
        return EET_ERROR;
    }
    m_rezim = rezim;
    return EET_OK;
}

std::string EetData::getZaklNepodlDph() const
{
    return m_zaklNepodlDph;
}

EETCODE EetData::setZaklNepodlDph(const std::string &zaklNepodlDph)
{
    if(!regexDouble(zaklNepodlDph))
    {
        m_chyba = "Chyba v Celková částka plnění osvobozených od DPH, ostatních plnění";
        return EET_ERROR;
    }
    m_zaklNepodlDph = zaklNepodlDph;
    return EET_OK;
}

EETCODE EetData::setZaklNepodlDph(double zaklNepodlDph)
{
    m_zaklNepodlDph = formatDouble(zaklNepodlDph);
    if(!regexDouble(m_zaklNepodlDph))
    {
        m_chyba = "Chyba v Celková částka plnění osvobozených od DPH, ostatních plnění";
        m_zaklNepodlDph = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getZaklDan1() const
{
    return m_zaklDan1;
}

EETCODE EetData::setZaklDan1(const std::string &zaklDan1)
{
    if(!regexDouble(zaklDan1))
    {
        m_chyba = "Chyba v Celkový základ daně se základní sazbou DPH";
        return EET_ERROR;
    }
    m_zaklDan1 = zaklDan1;
    return EET_OK;
}

EETCODE EetData::setZaklDan1(double zaklDan1)
{
    m_zaklDan1 = formatDouble(zaklDan1);
    if(!regexDouble(m_zaklDan1))
    {
        m_chyba = "Chyba v Celkový základ daně se základní sazbou DPH";
        m_zaklDan1 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getDan1() const
{
    return m_dan1;
}

EETCODE EetData::setDan1(const std::string &dan1)
{
    if(!regexDouble(dan1))
    {
        m_chyba = "Chyba v Celková DPH se základní sazbou";
        return EET_ERROR;
    }
    m_dan1 = dan1;
    return EET_OK;
}

EETCODE EetData::setDan1(double dan1)
{
    m_dan1 = formatDouble(dan1);
    if(!regexDouble(m_dan1))
    {
        m_chyba = "Chyba v Celková DPH se základní sazbou";
        m_dan1 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getZaklDan2() const
{
    return m_zaklDan2;
}

EETCODE EetData::setZaklDan2(const std::string &zaklDan2)
{
    if(!regexDouble(zaklDan2))
    {
        m_chyba = "Chyba v Celkový základ daně s první sníženou sazbou DPH";
        return EET_ERROR;
    }
    m_zaklDan2 = zaklDan2;
    return EET_OK;
}

EETCODE EetData::setZaklDan2(double zaklDan2)
{
    m_zaklDan2 = formatDouble(zaklDan2);
    if(!regexDouble(m_zaklDan2))
    {
        m_chyba = "Chyba v Celkový základ daně s první sníženou sazbou DPH";
        m_zaklDan2 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getDan2() const
{
    return m_dan2;
}

EETCODE EetData::setDan2(const std::string &dan2)
{
    if(!regexDouble(dan2))
    {
        m_chyba = "Chyba v Celková DPH s první sníženou sazbou";
        return EET_ERROR;
    }
    m_dan2 = dan2;
    return EET_OK;
}

EETCODE EetData::setDan2(double dan2)
{
    m_dan2 = formatDouble(dan2);
    if(!regexDouble(m_dan2))
    {
        m_chyba = "Chyba v Celková DPH s první sníženou sazbou";
        m_dan2 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getZaklDan3() const
{
    return m_zaklDan3;
}

EETCODE EetData::setZaklDan3(const std::string &zaklDan3)
{
    if(!regexDouble(zaklDan3))
    {
        m_chyba = "Chyba v Celkový základ daně s druhou sníženou sazbou DPH";
        return EET_ERROR;
    }
    m_zaklDan3 = zaklDan3;
    return EET_OK;
}

EETCODE EetData::setZaklDan3(double zaklDan3)
{
    m_zaklDan3 = formatDouble(zaklDan3);
    if(!regexDouble(m_zaklDan3))
    {
        m_chyba = "Chyba v Celkový základ daně s druhou sníženou sazbou DPH";
        m_zaklDan3 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getDan3() const
{
    return m_dan3;
}

EETCODE EetData::setDan3(const std::string &dan3)
{
    if(!regexDouble(dan3))
    {
        m_chyba = "Chyba v Celková DPH s druhou sníženou sazbou";
        return EET_ERROR;
    }
    m_dan3 = dan3;
    return EET_OK;
}

EETCODE EetData::setDan3(double dan3)
{
    m_dan3 = formatDouble(dan3);
    if(!regexDouble(m_dan3))
    {
        m_chyba = "Chyba v Celková DPH s druhou sníženou sazbou";
        m_dan3 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getCestSluz() const
{
    return m_cestSluz;
}

EETCODE EetData::setCestSluz(const std::string &cestSluz)
{
    if(!regexDouble(cestSluz))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro cestovní službu";
        return EET_ERROR;
    }
    m_cestSluz = cestSluz;
    return EET_OK;
}

EETCODE EetData::setCestSluz(double cestSluz)
{
    m_cestSluz = formatDouble(cestSluz);
    if(!regexDouble(m_cestSluz))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro cestovní službu";
        m_cestSluz = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getPouzitZboz1() const
{
    return m_pouzitZboz1;
}

EETCODE EetData::setPouzitZboz1(const std::string &pouzitZboz1)
{
    if(!regexDouble(pouzitZboz1))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou";
        return EET_ERROR;
    }
    m_pouzitZboz1 = pouzitZboz1;
    return EET_OK;
}

EETCODE EetData::setPouzitZboz1(double pouzitZboz1)
{
    m_pouzitZboz1 = formatDouble(pouzitZboz1);
    if(!regexDouble(m_pouzitZboz1))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží se základní sazbou";
        m_pouzitZboz1 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getPouzitZboz2() const
{
    return m_pouzitZboz2;
}

EETCODE EetData::setPouzitZboz2(const std::string &pouzitZboz2)
{
    if(!regexDouble(pouzitZboz2))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou";
        return EET_ERROR;
    }
    m_pouzitZboz2 = pouzitZboz2;
    return EET_OK;
}

EETCODE EetData::setPouzitZboz2(double pouzitZboz2)
{
    m_pouzitZboz2 = formatDouble(pouzitZboz2);
    if(!regexDouble(m_pouzitZboz2))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží s první sníženou sazbou";
        m_pouzitZboz2 = "";
        return EET_ERROR;
    }
    return EET_OK;
}

std::string EetData::getPouzitZboz3() const
{
    return m_pouzitZboz3;
}

EETCODE EetData::setPouzitZboz3(const std::string &pouzitZboz3)
{
    if(!regexDouble(pouzitZboz3))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou";
        return EET_ERROR;
    }
    m_pouzitZboz3 = pouzitZboz3;
    return EET_OK;
}

EETCODE EetData::setPouzitZboz3(double pouzitZboz3)
{
    m_pouzitZboz3 = formatDouble(pouzitZboz3);
    if(!regexDouble(m_pouzitZboz3))
    {
        m_chyba = "Chyba v Celková částka v režimu DPH pro prodej použitého zboží s druhou sníženou sazbou";
        m_pouzitZboz3 = "";
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
