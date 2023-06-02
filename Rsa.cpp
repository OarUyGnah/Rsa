#include "Rsa.h"

RSA *Rsa::read_file_to_rsa(std::string key_path, FILETYPE ft, KEYTYPE type)
{
    RSA *rsa = nullptr;
    switch (ft)
    {
    case FILETYPE::PEM:
        rsa = read_pem_file_to_rsa(key_path, type);
        break;

    case FILETYPE::DER:
        rsa = read_der_file_to_rsa(key_path, type);
        break;

    default:
        break;
    }
    return rsa;
}

bool Rsa::gen_key_file(std::string pub_path, std::string priv_path, FILETYPE ft)
{
    switch (ft)
    {
    case FILETYPE::PEM:
        return gen_key_pem_file(pub_path, priv_path);

    case FILETYPE::DER:
        return gen_key_der_file(pub_path, priv_path);

    default:
        break;
    }
    return false;
}

bool Rsa::pub_enc(std::string pub_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = read_file_to_rsa(pub_key_path, ft, KEYTYPE::PUBLIC);

    if (!rsa)
    {
        std::cout << "RSA* nullptr" << std::endl;
        return false;
    }

    out_len = RSA_public_encrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

bool Rsa::pub_enc(std::string &pub_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = Rsa::read_string_to_rsa(pub_key, KEYTYPE::PUBLIC);
    if (!rsa)
    {
        std::cout << "RSA* nullptr" << std::endl;
        return false;
    }

    out_len = RSA_public_encrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

bool Rsa::pri_enc(std::string pri_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{

    RSA *rsa = read_file_to_rsa(pri_key_path, ft, KEYTYPE::PRIVATE);
    if (!rsa)
        return false;
    out_len = RSA_private_encrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

bool Rsa::pri_enc(std::string &pri_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = Rsa::read_string_to_rsa(pri_key, KEYTYPE::PRIVATE);
    if (!rsa)
    {
        std::cout << "RSA* nullptr" << std::endl;
        return false;
    }

    out_len = RSA_private_encrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    // std::cout << "out_len = " << out_len << std::endl;
    RSA_free(rsa);
    return true;
}

bool Rsa::pub_dec(std::string pub_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = read_file_to_rsa(pub_key_path, ft, KEYTYPE::PUBLIC);

    if (!rsa)
        return false;
    out_len = RSA_public_decrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

bool Rsa::pub_dec(std::string &pub_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = read_string_to_rsa(pub_key, KEYTYPE::PUBLIC);
    if (!rsa)
    {
        std::cout << "RSA* nullptr" << std::endl;
        return false;
    }

    out_len = RSA_public_decrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

bool Rsa::pri_dec(std::string pri_key_path, FILETYPE ft, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = read_file_to_rsa(pri_key_path, ft, KEYTYPE::PRIVATE);
    if (!rsa)
        return false;
    out_len = RSA_private_decrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

bool Rsa::pri_dec(std::string &pri_key, const unsigned char *in, int in_len, unsigned char *out, int &out_len)
{
    RSA *rsa = Rsa::read_string_to_rsa(pri_key, KEYTYPE::PRIVATE);
    if (!rsa)
    {
        std::cout << "RSA* nullptr" << std::endl;
        return false;
    }

    out_len = RSA_private_decrypt(in_len, in, out, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    return true;
}

std::string Rsa::read_key_file_to_string(std::string keyfile_path, FILETYPE ft, KEYTYPE type)
{
    return ft == FILETYPE::PEM ? read_pem_file_to_string(keyfile_path, type) : read_der_file_to_string(keyfile_path, type);
}

RSA *Rsa::read_string_to_rsa(std::string &key_string, KEYTYPE type)
{
    BIO *bio = BIO_new_mem_buf(key_string.data(), key_string.size());
    RSA *rsa = nullptr;
    switch (type)
    {
    case KEYTYPE::PUBLIC:
        rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        // der 格式
        if (!rsa)
        {
            const char *p = key_string.data();
            const unsigned char **pp = (const unsigned char **)&p;
            rsa = d2i_RSAPublicKey(nullptr, pp, key_string.size());
        }
        break;
    case KEYTYPE::PRIVATE:
        rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
        if (!rsa)
        {
            const char *p = key_string.data();
            const unsigned char **pp = (const unsigned char **)&p;
            rsa = d2i_RSAPrivateKey(nullptr, pp, key_string.size());
        }
        break;
    default:
        break;
    }
    BIO_free(bio);
    return rsa;
}

RSA *Rsa::read_pem_file_to_rsa(std::string key_path, KEYTYPE type)
{
    BIO *bio = BIO_new_file(key_path.c_str(), "r");
    RSA *rsa = nullptr;
    switch (type)
    {
    case KEYTYPE::PUBLIC:
        rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        assert(rsa);
        break;
    case KEYTYPE::PRIVATE:
        rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
        break;
    default:
        break;
    }

    BIO_free(bio);
    if (!rsa)
    {
        return nullptr;
    }
    return rsa;
}

RSA *Rsa::read_der_file_to_rsa(std::string key_path, KEYTYPE type)
{
    std::ifstream ifs(key_path, std::ios_base::binary | std::ios::ate);
    int len = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::string key(len, '\0');
    ifs.read(&key[0], len);
    ifs.close();

    RSA *rsa = RSA_new();
    const char *p = key.data();
    const unsigned char **pp = (const unsigned char **)&p;
    if (type == KEYTYPE::PUBLIC)
    {
        rsa = d2i_RSAPublicKey(nullptr, pp, len);
    }
    else
    {
        rsa = d2i_RSAPrivateKey(nullptr, pp, len);
    }

    if (rsa == nullptr)
    {
        std::cout << "GetPubKey Failed!" << std::endl;
        return nullptr;
    }
    return rsa;
}
bool Rsa::gen_key_pem_file(std::string pub_path, std::string priv_path)
{
    RSA *rsa = RSA_new();
    rsa = RSA_generate_key(RSA_KEYSIZE, RSA_F4, nullptr, nullptr);
    BIO *bio_pub = BIO_new_file(pub_path.c_str(), "w");
    PEM_write_bio_RSAPublicKey(bio_pub, rsa);
    BIO *bio_pri = BIO_new_file(priv_path.c_str(), "w");
    PEM_write_bio_RSAPrivateKey(bio_pri, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio_pub);
    BIO_free(bio_pri);
}

bool Rsa::gen_key_der_file(std::string pub_path, std::string priv_path)
{
    RSA *rsa = RSA_new();
    rsa = RSA_generate_key(RSA_KEYSIZE, RSA_F4, nullptr, nullptr);

    unsigned char pubKeyData[RSA_KEYSIZE] = {0};
    int pubKeyLen = i2d_RSAPublicKey(rsa, nullptr);
    unsigned char *p = pubKeyData;
    pubKeyLen = i2d_RSAPublicKey(rsa, &p);

    unsigned char priKeyData[RSA_KEYSIZE] = {0};
    int priKeyLen = i2d_RSAPrivateKey(rsa, nullptr);
    unsigned char *p2 = priKeyData;
    priKeyLen = i2d_RSAPrivateKey(rsa, &p2);

    FILE *pubKeyFile = nullptr;
    pubKeyFile = fopen(pub_path.c_str(), "wb");
    if (pubKeyFile == nullptr)
    {
        std::cout << "fopen pubkey.key failed!" << std::endl;
        return false;
    }
    fwrite(pubKeyData, 1, pubKeyLen, pubKeyFile);
    fclose(pubKeyFile);

    FILE *priKeyFile = nullptr;
    priKeyFile = fopen(priv_path.c_str(), "wb");
    if (priKeyFile == nullptr)
    {
        std::cout << "fopen prikey.key failed!" << std::endl;
        return false;
    }
    fwrite(priKeyData, 1, priKeyLen, priKeyFile);
    fclose(priKeyFile);

    if (rsa != nullptr)
    {
        RSA_free(rsa);
        rsa = nullptr;
    }
    return true;
}

std::string Rsa::read_der_file_to_string(std::string keyfile_path, KEYTYPE type)
{
    std::ifstream ifs(keyfile_path, std::ios_base::binary | std::ios::ate);
    int len = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::string key(len, '\0');
    ifs.read(&key[0], len);
    ifs.close();
    return key;
}

std::string Rsa::read_pem_file_to_string(std::string keyfile_path, KEYTYPE type)
{
    std::ifstream ifs(keyfile_path);
    return std::string((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
}