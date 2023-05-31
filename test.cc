#include "Rsa.h"
#include "openssl/pem.h"
#include <iostream>
#include <fstream>
using std::cout;
using std::endl;
void generateRSAKeyPair(std::string publicKeyFile, std::string privateKeyFile, int keyLength)
{
    // RSA *rsa = RSA_generate_key(keyLength, RSA_F4, NULL, NULL);

    // // 生成公钥
    // BIO *bio = BIO_new_file(publicKeyFile.c_str(), "w+");
    // PEM_write_bio_RSAPublicKey(bio, rsa);
    // BIO_free_all(bio);

    // // 生成私钥
    // bio = BIO_new_file(privateKeyFile.c_str(), "w+");
    // PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    // BIO_free_all(bio);

    // RSA_free(rsa);
    Rsa rsa;
    rsa.gen_key_file("pub.key", "pri.key");
}

// void loadRSAKeyPair(std::string publicKeyFile, std::string privateKeyFile) {
//     Rsa rsa;
//     rsa.loadKeyFile("pub.key","pri.key");
// }

void pubenc_pridec()
{
    Rsa rsa;
    Rsa::gen_key_file("pub.key", "pri.key", Rsa::FILETYPE::DER);
    // rsa.gen_key_file();
    std::string plain = "123";
    // std::string enctext;
    // std::string dectext;
    unsigned char enc_str[1024];
    unsigned char dec_str[1024];
    int out_len = 0;
    // rsa.loadKeyFile("pub.key","pri.key");
    if (Rsa::pub_enc("pub.key", Rsa::FILETYPE::DER, (const unsigned char *)plain.c_str(), plain.size(), enc_str, out_len))
        cout << "enc successful" << endl;
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", enc_str[i]);
    }
    printf("\n");
    int len = out_len;
    if (Rsa::pri_dec("pri.key", Rsa::FILETYPE::DER, (const unsigned char *)enc_str, len, dec_str, out_len))
        cout << "dec successful" << endl;
    cout << std::string((char *)dec_str, out_len) << endl;
}

void prienc_pubdec()
{
    Rsa rsa;
    Rsa::gen_key_file("pub.key", "pri.key",Rsa::FILETYPE::DER);
    std::string plain = "123";
    unsigned char enc_str[1024];
    unsigned char dec_str[1024];
    int out_len = 0;
    if (Rsa::pri_enc("pri.key", Rsa::FILETYPE::DER, (const unsigned char *)plain.c_str(), plain.size(), enc_str, out_len))
        cout << "enc successful" << endl;
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", enc_str[i]);
    }
    printf("\n");
    int len = out_len;
    if (Rsa::pub_dec("pub.key", Rsa::FILETYPE::DER, (const unsigned char *)enc_str, len, dec_str, out_len))
        cout << "dec successful" << endl;
    cout << std::string((char *)dec_str, out_len) << endl;
}

void pem_test()
{
    Rsa::gen_key_file("pub.pem", "pri.pem", Rsa::FILETYPE::PEM);
    std::string plain = "123";
    unsigned char enc_str[1024];
    unsigned char dec_str[1024];
    int out_len = 0;
    if (Rsa::pub_enc("pub.pem", Rsa::FILETYPE::PEM, (const unsigned char *)plain.c_str(), plain.size(), enc_str, out_len))
    {
        cout << "enc successful" << endl;
    }
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", enc_str[i]);
    }
    printf("\n");
    int len = out_len;
    if (Rsa::pri_dec("pri.pem", Rsa::FILETYPE::PEM, (const unsigned char *)enc_str, len, dec_str, out_len))
        cout << "dec successful" << endl;
    cout << std::string((char *)dec_str, out_len) << endl;
}

void read_file()
{
    // cout << Rsa::read_key_file_to_string("pri.pem", Rsa::FILETYPE::PEM, Rsa::KEYTYPE::PRIVATE) << endl;
    // cout << Rsa::read_key_file_to_string("pub.pem", Rsa::FILETYPE::PEM, Rsa::KEYTYPE::PUBLIC) << endl;
    auto pri_key = Rsa::read_key_file_to_string("pri.pem", Rsa::FILETYPE::PEM, Rsa::KEYTYPE::PRIVATE);
    auto pub_key = Rsa::read_key_file_to_string("pub.pem", Rsa::FILETYPE::PEM, Rsa::KEYTYPE::PUBLIC);
    std::string plain = "123";
    unsigned char enc_str[1024];
    unsigned char dec_str[1024];
    int out_len = 0;
    if (Rsa::pub_enc(pub_key, (const unsigned char *)plain.c_str(), plain.size(), enc_str, out_len))
    {
        cout << "enc successful" << endl;
    }
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", enc_str[i]);
    }
    cout << endl;
    int len = out_len;
    if (Rsa::pri_dec(pri_key, (const unsigned char *)enc_str, len, dec_str, out_len))
    {
        cout << "dec successful" << endl;
    }
    cout << std::string((char *)dec_str, out_len) << endl;
    // cout << Rsa::read_key_file_to_string("pri.key", Rsa::FILETYPE::DER, Rsa::KEYTYPE::PRIVATE) << endl;
    // cout << Rsa::read_key_file_to_string("pub.key", Rsa::FILETYPE::DER, Rsa::KEYTYPE::PUBLIC) << endl;
    pri_key = Rsa::read_key_file_to_string("pri.key", Rsa::FILETYPE::DER, Rsa::KEYTYPE::PRIVATE);
    
    pub_key = Rsa::read_key_file_to_string("pub.key", Rsa::FILETYPE::DER, Rsa::KEYTYPE::PUBLIC);
    out_len = 0;
    if (Rsa::pub_enc(pub_key, (const unsigned char *)plain.c_str(), plain.size(), enc_str, out_len))
    {
        cout << "enc successful" << endl;
    }
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", enc_str[i]);
    }
    cout << endl;
    len = out_len;
    if (Rsa::pri_dec(pri_key, (const unsigned char *)enc_str, len, dec_str, out_len))
    {
        cout << "dec successful" << endl;
    }
    cout << std::string((char *)dec_str, out_len) << endl;
}

void read_stringkey()
{
    // DER 类型读取
    // auto pri_key = Rsa::read_key_file_to_string("pri.key",Rsa::FILETYPE::DER,Rsa::KEYTYPE::PRIVATE);
    // auto pub_key = Rsa::read_key_file_to_string("pub.key",Rsa::FILETYPE::DER,Rsa::KEYTYPE::PUBLIC);

    // PEM 类型读取
    auto pri_key = Rsa::read_key_file_to_string("../key/oar_pri.pem",Rsa::FILETYPE::PEM,Rsa::KEYTYPE::PRIVATE);
    auto pub_key = Rsa::read_key_file_to_string("../key/oar_pub.pem",Rsa::FILETYPE::PEM,Rsa::KEYTYPE::PUBLIC);
    std::string plain = "123";
    unsigned char enc_str[1024];
    unsigned char dec_str[1024];
    int out_len = 0;
    if (Rsa::pub_enc(pub_key, (const unsigned char *)plain.c_str(), plain.size(), enc_str, out_len))
    {
        cout << "enc successful" << endl;
    }
    for (int i = 0; i < out_len; i++)
    {
        printf("%02x", enc_str[i]);
    }
    cout << endl;
    int len = out_len;
    if (Rsa::pri_dec(pri_key, (const unsigned char *)enc_str, len, dec_str, out_len))
    {
        cout << "dec successful" << endl;
    }
    cout << std::string((char *)dec_str, out_len) << endl;
}
int main(int argc, char const *argv[])
{
    printf("===================pubenc_pridec===================\n");
    pubenc_pridec();
    printf("===================prienc_pubdec===================\n");
    prienc_pubdec();
    printf("===================pem_test===================\n");
    pem_test();
    printf("===================read_file===================\n");
    read_file();
    printf("===================read_stringkey===================\n");
    read_stringkey();
    return 0;
}