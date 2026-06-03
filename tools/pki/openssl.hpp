#pragma once

#include "keys.hpp"
#include <vanetza/security/openssl_wrapper.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cassert>
#include <filesystem>
#include <functional>
#include <memory>

namespace vanetza
{
namespace pki
{

template<typename T> std::function<void(T*)> openssl_deleter();

template<> std::function<void(BIGNUM*)> openssl_deleter<BIGNUM>();

template<> std::function<void(BIO*)> openssl_deleter<BIO>();

template<> std::function<void(BN_CTX*)> openssl_deleter<BN_CTX>();

template<> std::function<void(EC_GROUP*)> openssl_deleter<EC_GROUP>();

template<> std::function<void(EC_KEY*)> openssl_deleter<EC_KEY>();

template<> std::function<void(EC_POINT*)> openssl_deleter<EC_POINT>();

template<> std::function<void(ECDSA_SIG*)> openssl_deleter<ECDSA_SIG>();

template<> std::function<void(EVP_PKEY*)> openssl_deleter<EVP_PKEY>();

template<> std::function<void(EVP_CIPHER_CTX*)> openssl_deleter<EVP_CIPHER_CTX>();

using OpenSslException = vanetza::security::openssl::Exception;

template<typename T> class OpenSslPointer
{
public:
    explicit OpenSslPointer(T* raw) : m_ptr(raw, openssl_deleter<T>())
    {
        if (raw == nullptr) {
            throw OpenSslException(ERR_get_error());
        }
    }

    OpenSslPointer(T* raw, const char* errmsg) : m_ptr(raw, openssl_deleter<T>())
    {
        if (raw == nullptr) {
            throw OpenSslException(ERR_get_error(), errmsg);
        }
    }

    OpenSslPointer(T* raw, const std::string& errmsg) : OpenSslPointer(raw, errmsg.c_str())
    {
    }

    T* raw()
    {
        assert(m_ptr);
        return m_ptr.get();
    }

    const T* raw() const
    {
        assert(m_ptr);
        return m_ptr.get();
    }

private:
    std::unique_ptr<T, std::function<void(T*)>> m_ptr;
};

int openssl_nid(KeyType);
KeyType openssl_nid2key(int);
KeyType openssl_key_type_from_group_name(const char*);
void openssl_result(int rc, const char*);

OpenSslPointer<EC_POINT> make_ec_point(const PublicKey&);
OpenSslPointer<EC_KEY> make_ec_key(const PublicKey&);
OpenSslPointer<EC_KEY> make_ec_key(const PrivateKey&);
OpenSslPointer<BIGNUM> make_bignum(const ByteBuffer&);
PublicKey make_public_key(const EC_KEY*);
ByteBuffer make_buffer(const BIGNUM*);
ByteBuffer make_buffer(const BIGNUM*, std::size_t length);

/**
 * \brief Open (truncate) a file as owner-only and wrap its descriptor in a BIO.
 *
 * Prevents that the file is ever momentarily readable by other users.
 * \param path file to create or truncate
 * \return BIO writing to the file; closing the BIO closes the descriptor
 * \throws std::runtime_error if the file cannot be created
 * \throws OpenSslException if the BIO cannot be allocated
 */
OpenSslPointer<BIO> make_owner_only_bio(const std::filesystem::path& path);

} // namespace pki
} // namespace vanetza
