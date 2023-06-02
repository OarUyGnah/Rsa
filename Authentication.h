#ifndef AUTHENTICATION
#define AUTHENTICATION
#include "Rsa.h"
#include "AdHocLogger.h"
#include <memory>

class Authentication
{

public:
    enum KEYFROM
    {
        LOCAL = 0,
        REMOTE = 1,
    };
    // static std::shared_ptr<Authentication> instance(std::string pub_key_path, std::string pri_key_path, Rsa::FILETYPE ft = Rsa::FILETYPE::PEM)
    // {
    //     static std::shared_ptr<Authentication> auth(new Authentication(pub_key_path, pri_key_path, ft));
    //     return auth;
    // }
    static std::shared_ptr<Authentication> instance()
    {
        static std::shared_ptr<Authentication> auth(new Authentication());
        return auth;
    }

    // bool authenticate(std::string enc_text);

    std::string pub_enc(std::string plain_text, KEYFROM from);

    std::string pri_dec(std::string enc_text, KEYFROM from);

    std::string pub_dec(std::string enc_text, KEYFROM from);

    std::string pri_enc(std::string plain_text, KEYFROM from);

    std::string get_pub_key();

    std::string get_pri_key();

    void set_local_key_path(std::string pub_path, std::string pri_path, Rsa::FILETYPE ft = Rsa::FILETYPE::PEM);

    void set_local_pub_key_path(std::string &pub_path, Rsa::FILETYPE ft = Rsa::FILETYPE::PEM);

    void set_local_pri_key_path(std::string &pri_path, Rsa::FILETYPE ft = Rsa::FILETYPE::PEM);

    void set_local_pub_key(std::string &pub_key);

    void set_local_pri_key(std::string &pri_key);

    void set_remote_pub_key(std::string &pub_key);

    void set_remote_pri_key(std::string &pri_key);

    std::string base64_encode(const unsigned char *data, size_t data_len)
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new(BIO_s_mem());
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, data, data_len);
        BIO_flush(b64);
        BUF_MEM *mem_buf;
        BIO_get_mem_ptr(mem, &mem_buf);
        std::string result(mem_buf->data, mem_buf->length);
        BIO_free_all(b64);
        return result;
    }

public:
    Authentication() = default;
    Authentication(std::string pub_key_path, std::string pri_key_path, Rsa::FILETYPE ft = Rsa::FILETYPE::PEM);
    ~Authentication() = default;

private:
    std::string m_localPubKey;
    std::string m_localPriKey;
    std::string m_remotePubKey;
    std::string m_remotePriKey;
};

#endif // !AUTHENTICATION