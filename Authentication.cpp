#include "Authentication.h"


Authentication::Authentication(std::string pub_key_path, std::string pri_key_path, Rsa::FILETYPE ft)
    : m_localPubKey(Rsa::read_key_file_to_string(pub_key_path, ft, Rsa::KEYTYPE::PUBLIC)), m_localPriKey(Rsa::read_key_file_to_string(pri_key_path, ft, Rsa::KEYTYPE::PRIVATE))
{
}

// bool Authentication::authenticate(std::string enc_text)
// {
//     // 验证公钥
//     int out_len = -1;
//     unsigned char buf[1024];
//     if (Rsa::pri_dec(m_localPriKey, (const unsigned char *)enc_text.data(), enc_text.size(), buf, out_len))
//     {
//         ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
//     }
//     return true;
// }

std::string Authentication::pub_enc(std::string plain_text, KEYFROM from)
{
    int out_len = -1;
    unsigned char buf[1024] = {0};
    switch (from)
    {
    case KEYFROM::LOCAL:
        if (Rsa::pub_enc(m_localPubKey, (const unsigned char *)plain_text.data(), plain_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    case KEYFROM::REMOTE:
        if (Rsa::pub_enc(m_remotePubKey, (const unsigned char *)plain_text.data(), plain_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    default:
        break;
    }

    return std::string((char *)buf, out_len);
}

std::string Authentication::pri_dec(std::string enc_text, KEYFROM from)
{
    int out_len = -1;
    unsigned char buf[1024] = {0};
    switch (from)
    {
    case KEYFROM::LOCAL:
        if (Rsa::pri_dec(m_localPriKey, (const unsigned char *)enc_text.data(), enc_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    case KEYFROM::REMOTE:
        if (Rsa::pri_dec(m_remotePriKey, (const unsigned char *)enc_text.data(), enc_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    default:
        break;
    }
    return std::string((char *)buf, out_len);
}

std::string Authentication::pub_dec(std::string enc_text, KEYFROM from)
{
    int out_len = -1;
    unsigned char buf[1024] = {0};
    switch (from)
    {
    case KEYFROM::LOCAL:
        if (Rsa::pub_dec(m_localPubKey, (const unsigned char *)enc_text.data(), enc_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    case KEYFROM::REMOTE:
        if (Rsa::pub_dec(m_remotePubKey, (const unsigned char *)enc_text.data(), enc_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    default:
        break;
    }
    return std::string((char *)buf, out_len);
}

std::string Authentication::pri_enc(std::string plain_text, KEYFROM from)
{
    int out_len = -1;
    unsigned char buf[1024] = {0};
    switch (from)
    {
    case KEYFROM::LOCAL:
        if (Rsa::pri_enc(m_localPriKey, (const unsigned char *)plain_text.data(), plain_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    case KEYFROM::REMOTE:
        if (Rsa::pri_enc(m_remotePriKey, (const unsigned char *)plain_text.data(), plain_text.size(), buf, out_len))
        {
            // ADHOCLOG(Logger::LEVEL_Debug, "authenticate", "pri_dec success");
        }
        break;
    default:
        break;
    }
    return std::string((char *)buf, out_len);
}

std::string Authentication::get_pub_key()
{
    return m_localPubKey;
}

std::string Authentication::get_pri_key()
{
    return m_localPriKey;
}

void Authentication::set_local_key_path(std::string pub_path, std::string pri_path, Rsa::FILETYPE ft) {
    m_localPubKey = std::move(Rsa::read_key_file_to_string(pub_path, ft, Rsa::KEYTYPE::PUBLIC));
    m_localPriKey = std::move(Rsa::read_key_file_to_string(pri_path, ft, Rsa::KEYTYPE::PRIVATE));
}

void Authentication::set_local_pub_key_path(std::string &pub_path, Rsa::FILETYPE ft)
{
    m_localPubKey = std::move(Rsa::read_key_file_to_string(pub_path, ft, Rsa::KEYTYPE::PUBLIC));
}

void Authentication::set_local_pri_key_path(std::string &pri_path, Rsa::FILETYPE ft)
{
    m_localPriKey = std::move(Rsa::read_key_file_to_string(pri_path, ft, Rsa::KEYTYPE::PRIVATE));
}

void Authentication::set_local_pub_key(std::string &pub_key)
{
    m_localPubKey = pub_key;
}

void Authentication::set_local_pri_key(std::string &pri_key)
{
    m_localPriKey = pri_key;
}

void Authentication::set_remote_pub_key(std::string &pub_key)
{
    m_remotePubKey = pub_key;
}

void Authentication::set_remote_pri_key(std::string &pri_key)
{
    m_remotePriKey = pri_key;
}