#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <cassert>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

namespace vanetza
{
namespace security
{
namespace openssl
{

void check(bool valid)
{
    if (!valid) {
        throw Exception();
    }
}

Exception::Exception() : Exception(ERR_get_error())
{
}

Exception::Exception(code_type err) :
    std::runtime_error(ERR_reason_error_string(err))
{
}

BigNumber::BigNumber() : bignum(BN_new())
{
    check(bignum != nullptr);
}

BigNumber::BigNumber(const uint8_t* arr, std::size_t len) : bignum(BN_bin2bn(arr, len, nullptr))
{
    check(bignum != nullptr);
}

BigNumber::~BigNumber()
{
    BN_clear_free(bignum);
}

BigNumberContext::BigNumberContext() : ctx(BN_CTX_new())
{
    check(ctx != nullptr);
    BN_CTX_start(ctx);
}

BigNumberContext::~BigNumberContext()
{
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

Point::Point(const EC_GROUP* group) : point(EC_POINT_new(group))
{
    check(point != nullptr);
}

Point::Point(Point&& other) : point(nullptr)
{
    std::swap(point, other.point);
}

Point& Point::operator=(Point&& other)
{
    std::swap(point, other.point);
    return *this;
}

Point::~Point()
{
    EC_POINT_free(point);
}

Group::Group(int nid) : group(EC_GROUP_new_by_curve_name(nid))
{
    check(group != nullptr);
}

Group::~Group()
{
    EC_GROUP_clear_free(group);
}

Signature::Signature(ECDSA_SIG* sig) : signature(sig)
{
    check(signature);
}

Signature::Signature(const EcdsaSignature& ecdsa) :
    Signature(convert_for_signing(ecdsa.R), ecdsa.s)
{
}

Signature::Signature(const security::Signature& sig) :
    Signature(sig.r, sig.s)
{
}

Signature::Signature(const ByteBuffer& r, const ByteBuffer& s) :
    signature(ECDSA_SIG_new())
{
    check(signature);
    // ownership of big numbers is transfered by calling ECDSA_SIG_set0!
    BIGNUM* bn_r = BN_bin2bn(r.data(), r.size(), nullptr);
    BIGNUM* bn_s = BN_bin2bn(s.data(), s.size(), nullptr);
    if (!ECDSA_SIG_set0(signature, bn_r, bn_s)) {
        BN_clear_free(bn_r);
        BN_clear_free(bn_s);
        throw Exception();
    }
}

Signature::Signature(Signature&& other) : signature(nullptr)
{
    std::swap(signature, other.signature);
}

Signature& Signature::operator=(Signature&& other)
{
    std::swap(signature, other.signature);
    return *this;
}

Signature::~Signature()
{
    ECDSA_SIG_free(signature);
}

Key::Key() : eckey(EC_KEY_new())
{
    check(eckey);
}

Key::Key(int nid) : eckey(EC_KEY_new_by_curve_name(nid))
{
    check(eckey);
}

Key::Key(EC_KEY* key) : eckey(key)
{
}

Key::Key(Key&& other) : eckey(nullptr)
{
    std::swap(eckey, other.eckey);
}

Key& Key::operator=(Key&& other)
{
    std::swap(eckey, other.eckey);
    return *this;
}

Key::~Key()
{
    EC_KEY_free(eckey);
}

Bio::Bio(BIO* bio) : bio(bio)
{
}

Bio::Bio(Bio&& other) : bio(nullptr)
{
    std::swap(bio, other.bio);
}

Bio& Bio::operator=(Bio&& other)
{
    std::swap(bio, other.bio);
    return *this;
}

Bio::~Bio()
{
    BIO_free(bio);
}

EvpKey::EvpKey(EVP_PKEY* pkey) : pkey(pkey)
{
}

EvpKey::EvpKey(EvpKey&& other) : pkey(nullptr)
{
    std::swap(pkey, other.pkey);
}

EvpKey& EvpKey::operator=(EvpKey&& other)
{
    std::swap(pkey, other.pkey);
    return *this;
}

EvpKey::~EvpKey()
{
    EVP_PKEY_free(pkey);
}

} // namespace openssl
} // namespace security
} // namespace vanetza
