#include <string>
#include <iostream>
#include <assert.h>
#include <fstream>
#include "openssl/rsa.h"
#include "openssl/pem.h"

#define RSA_KEYSIZE 1024

struct Rsa
{
public:
    enum KEYTYPE
    {
        PUBLIC = 0,
        PRIVATE = 1,
    };
    enum FILETYPE
    {
        PEM = 0,
        DER = 1,
    };

    Rsa() = default;

    ~Rsa() = default;

    static RSA *read_file_to_rsa(std::string pub_key_path, FILETYPE ft, KEYTYPE type);

    static bool gen_key_file(std::string pub_path, std::string priv_path, FILETYPE ft = FILETYPE::PEM);

    static bool pub_enc(std::string pub_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len);
    static bool pub_enc(std::string &pub_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len);

    static bool pri_enc(std::string pri_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len);
    static bool pri_enc(std::string &pri_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len);

    static bool pub_dec(std::string pub_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len);
    static bool pub_dec(std::string &pub_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len);

    static bool pri_dec(std::string pri_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len);
    static bool pri_dec(std::string &pri_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len);

    static std::string read_key_file_to_string(std::string keyfile_path, FILETYPE ft, KEYTYPE type);

    static RSA *read_string_to_rsa(std::string &key_string, KEYTYPE type);

private:
    static RSA *read_pem_file_to_rsa(std::string key_path, KEYTYPE type);

    static RSA *read_der_file_to_rsa(std::string key_path, KEYTYPE type);

    static bool gen_key_pem_file(std::string pub_path, std::string priv_path);

    static bool gen_key_der_file(std::string pub_path, std::string priv_path);

    static std::string read_der_file_to_string(std::string keyfile_path, KEYTYPE type);

    static std::string read_pem_file_to_string(std::string keyfile_path, KEYTYPE type);
};