#ifndef OPENSSL_WRAPPER_HPP_GUFJGICT
#define OPENSSL_WRAPPER_HPP_GUFJGICT

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/key_type.hpp>
#include <boost/core/noncopyable.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace vanetza
{
namespace security
{

// forward declaration
struct EcdsaSignature;
struct PublicKey;
struct Signature;

namespace openssl
{

/**
 * Check valid condition
 * \param valid If false stored OpenSSL error will be thrown
 */
void check(bool valid);


class Exception : public std::runtime_error
{
public:
    using code_type = decltype(ERR_get_error());

    Exception();
    explicit Exception(code_type err);
    explicit Exception(const std::string& msg);
    explicit Exception(code_type, const std::string& msg);
    ~Exception() override = default;

    code_type error_code() const { return m_error; }
    const char* reason() const;
    const char* library() const;

private:
    code_type m_error = 0;
};


class BigNumber : private boost::noncopyable
{
public:
    BigNumber();
    ~BigNumber();

    explicit BigNumber(const ByteBuffer& buf) :
        BigNumber(buf.data(), buf.size())
    {
    }

    template<std::size_t N>
    explicit BigNumber(const std::array<uint8_t, N>& bin) :
        BigNumber(bin.data(), bin.size())
    {
    }

    operator BIGNUM*() { return bignum; }

private:
    BigNumber(const uint8_t*, std::size_t);

    BIGNUM* bignum;
};


class BigNumberContext : private boost::noncopyable
{
public:
    BigNumberContext();
    ~BigNumberContext();

    operator BN_CTX*() { return ctx; }

private:
    BN_CTX* ctx;
};


class Group : private boost::noncopyable
{
public:
    explicit Group(int nid);
    ~Group();

    operator EC_GROUP*() { return group; }

private:
    EC_GROUP* group;
};


class Point : private boost::noncopyable
{
public:
    explicit Point(const EC_GROUP* group);
    Point(Point&&) noexcept;
    Point& operator=(Point&&) noexcept;
    ~Point();

    operator EC_POINT*() { return point; }

private:
    EC_POINT* point;
};


class Signature : private boost::noncopyable
{
public:
    explicit Signature(ECDSA_SIG* sig);
    explicit Signature(const EcdsaSignature& sig);
    explicit Signature(const security::Signature& sig);
    Signature(Signature&&) noexcept;
    Signature& operator=(Signature&&) noexcept;
    ~Signature();

    operator const ECDSA_SIG*() const { return signature; }
    const ECDSA_SIG* operator->() const { return signature; }
    ECDSA_SIG* operator->() { return signature; }
    explicit operator bool() const { return signature != nullptr; }

private:
    Signature(const ByteBuffer& r, const ByteBuffer& s);

    ECDSA_SIG* signature;
};


class Key
{
public:
    Key();
    explicit Key(int nid);
    explicit Key(EC_KEY* key);
    // non-copyable
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    // but movable
    Key(Key&&) noexcept;
    Key& operator=(Key&&) noexcept;
    ~Key();

    operator EC_KEY*() { return eckey; }
    explicit operator bool() const { return eckey != nullptr; }

private:
    EC_KEY* eckey;
};


class Bio : private boost::noncopyable
{
public:
    explicit Bio(BIO* bio);
    Bio(Bio&&) noexcept;
    Bio& operator=(Bio&&) noexcept;
    ~Bio();

    operator BIO*() { return bio; }
    explicit operator bool() const { return bio != nullptr; }

private:
    BIO* bio;
};


class EvpKey : private boost::noncopyable
{
public:
    explicit EvpKey(EVP_PKEY* pkey);
    EvpKey(EvpKey&&) noexcept;
    EvpKey& operator=(EvpKey&&) noexcept;
    ~EvpKey();

    operator EVP_PKEY*() { return pkey; }
    explicit operator bool() const { return pkey != nullptr; }

private:
    EVP_PKEY* pkey;
};

// releases OpenSSL objects, unlike Key a failed allocation yields nullptr instead of an exception
struct Deleter
{
    void operator()(BIGNUM* bn) const { BN_free(bn); }
    void operator()(EC_KEY* key) const { EC_KEY_free(key); }
    void operator()(EC_POINT* point) const { EC_POINT_free(point); }
    void operator()(ECDSA_SIG* sig) const { ECDSA_SIG_free(sig); }
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

template<typename T>
using Ptr = std::unique_ptr<T, Deleter>;

/**
 * Get OpenSSL's identifier of a key type's curve
 * \param key key type
 * \return curve NID
 * \throw std::runtime_error for unknown key type
 */
int nid(KeyType key);

/**
 * Build curve point of a public key
 * \param group curve of point
 * \param key public key
 * \return point or nullptr if key is malformed or not on the curve
 */
Ptr<EC_POINT> build_point(const EC_GROUP* group, const PublicKey& key);

} // namespace openssl
} // namespace security
} // namespace vanetza

#endif /* OPENSSL_WRAPPER_HPP_GUFJGICT */

