#include "openssl_security_module.hpp"
#include "credential_storage.hpp"
#include "ecies.hpp"
#include "openssl.hpp"
#include <vanetza/security/key_type.hpp>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace vanetza
{
namespace pki
{

namespace
{

constexpr std::size_t aes128_ccm_key_length = 16;
constexpr std::size_t nonce_length = 12;
constexpr std::size_t auth_tag_length = 16;

ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data)
{
    ByteBuffer hmac;
    hmac.resize(Sha256Hash::length);
    unsigned hmac_len = 0;
    if (!HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &hmac_len)) {
        throw OpenSslException(ERR_get_error(), "HMAC");
    } else if (hmac_len != hmac.size()) {
        throw std::runtime_error("invalid length of HMAC");
    }

    static_assert(Sha256Hash::length >= auth_tag_length, "length of authentication tag exceeds SHA-256 hash");
    hmac.resize(auth_tag_length);
    return hmac;
}

Sha256Hash calculate_sha256_hash(const ByteBuffer& data)
{
    Sha256Hash hash;
    SHA256(data.data(), data.size(), hash.octets.data());
    return hash;
}

class OpenSslEciesContext : public SecurityModule::EciesContext
{
public:
    OpenSslEciesContext(const PublicKey& receiver, const Sha256Hash& info) :
        m_ephemeral(EC_KEY_new_by_curve_name(openssl_nid(receiver.type))), m_recipient(receiver)
    {
        openssl_result(EC_KEY_generate_key(m_ephemeral.raw()), "EC_KEY_generate_key");
        openssl_result(EC_KEY_check_key(m_ephemeral.raw()), "EC_KEY_check_key");
        calculate_shared_secret(receiver);

        m_aes_key.resize(aes128_ccm_key_length);
        openssl_result(RAND_bytes(m_aes_key.data(), m_aes_key.size()), "RAND_bytes");
        m_nonce.resize(nonce_length);
        openssl_result(RAND_bytes(m_nonce.data(), m_nonce.size()), "RAND_bytes");
        encrypt_key(info);
    }

    PublicKey ephemeral_public_key() const override
    {
        return make_public_key(m_ephemeral.raw());
    }

    PublicKey recipient_public_key() const override
    {
        return m_recipient;
    }

    ByteBuffer shared_secret() const override
    {
        return m_shared_secret;
    }

    ByteBuffer encrypted_key() const override
    {
        return m_encrypted_key;
    }

    ByteBuffer authentication_tag() const override
    {
        return m_authentication_tag;
    }

    ByteBuffer nonce() const override
    {
        return m_nonce;
    }

    void nonce(const ByteBuffer& nonce) override
    {
        if (nonce.size() != nonce_length) {
            throw std::runtime_error("size of given nonce is invalid");
        }
        m_nonce = nonce;
    }

    ByteBuffer encrypt(const ByteBuffer& plaintext) override
    {
        OpenSslPointer<EVP_CIPHER_CTX> ctx { EVP_CIPHER_CTX_new() };
        openssl_result(EVP_CIPHER_CTX_init(ctx.raw()), "EVP_CIPHER_CTX_init");
        openssl_result(EVP_EncryptInit(ctx.raw(), EVP_aes_128_ccm(), nullptr, nullptr), "EVP_EncryptInit(CCM)");
        openssl_result(EVP_CIPHER_CTX_ctrl(ctx.raw(), EVP_CTRL_CCM_SET_TAG, auth_tag_length, nullptr),
            "EVP_CIPHER_CTX_ctrl(CCM_SET_TAG)");
        openssl_result(EVP_CIPHER_CTX_ctrl(ctx.raw(), EVP_CTRL_CCM_SET_IVLEN, nonce_length, nullptr),
            "EVP_CIPHER_CTX_ctrl(CCM_SET_IVLEN)");
        openssl_result(EVP_EncryptInit(ctx.raw(), nullptr, m_aes_key.data(), m_nonce.data()), "EVP_EncryptInit(key)");

        ByteBuffer ciphertext;
        ciphertext.resize(plaintext.size() + auth_tag_length);
        int ciphertext_length = 0;
        openssl_result(EVP_EncryptUpdate(ctx.raw(), ciphertext.data(), &ciphertext_length, plaintext.data(),
                           plaintext.size()),
            "EVP_EncryptUpdate");
        assert(ciphertext_length == ciphertext.size() - auth_tag_length);
        int final_length = 0;
        openssl_result(EVP_EncryptFinal(ctx.raw(), ciphertext.data() + ciphertext_length, &final_length),
            "EVP_EncryptFinal");
        assert(final_length == 0);
        openssl_result(EVP_CIPHER_CTX_ctrl(ctx.raw(), EVP_CTRL_CCM_GET_TAG, auth_tag_length,
                           ciphertext.data() + ciphertext_length),
            "EVP_CIPHER_CTX_ctrl(CCM_GET_TAG)");

        return ciphertext;
    }

    ByteBuffer decrypt(const std::uint8_t* ciphertext, std::size_t ciphertext_length) override
    {
        if (ciphertext_length < auth_tag_length) {
            throw std::runtime_error("cipher text is too short");
        }
        int plaintext_length = ciphertext_length - auth_tag_length;
        const std::uint8_t* auth_tag = ciphertext + plaintext_length;

        OpenSslPointer<EVP_CIPHER_CTX> ctx { EVP_CIPHER_CTX_new() };
        openssl_result(EVP_CIPHER_CTX_init(ctx.raw()), "EVP_CIPHER_CTX_init");
        openssl_result(EVP_DecryptInit(ctx.raw(), EVP_aes_128_ccm(), nullptr, nullptr), "EVP_DecryptInit(CCM)");
        openssl_result(EVP_CIPHER_CTX_ctrl(ctx.raw(), EVP_CTRL_CCM_SET_TAG, auth_tag_length,
                           const_cast<std::uint8_t*>(auth_tag)),
            "EVP_CIPHER_CTX_ctrl(CCM_SET_TAG)");
        openssl_result(EVP_CIPHER_CTX_ctrl(ctx.raw(), EVP_CTRL_CCM_SET_IVLEN, nonce_length, nullptr),
            "EVP_CIPHER_CTX_ctrl(CCM_SET_IVLEN)");
        openssl_result(EVP_DecryptInit(ctx.raw(), nullptr, m_aes_key.data(), m_nonce.data()), "EVP_DecryptInit(key)");

        ByteBuffer plaintext;
        plaintext.resize(plaintext_length);
        openssl_result(EVP_DecryptUpdate(ctx.raw(), plaintext.data(), &plaintext_length, ciphertext, plaintext_length),
            "EVP_DecryptUpdate");
        assert(plaintext_length == plaintext.size());

        return plaintext;
    }

    void calculate_shared_secret(const PublicKey& receiver)
    {
        const EC_GROUP* group = EC_KEY_get0_group(m_ephemeral.raw());
        int degree = EC_GROUP_get_degree(group);
        m_shared_secret.resize((degree + 7) / 8);
        int computed = ECDH_compute_key(m_shared_secret.data(), m_shared_secret.size(), make_ec_point(receiver).raw(),
            m_ephemeral.raw(), nullptr);
        if (computed != m_shared_secret.size()) {
            throw OpenSslException(ERR_get_error(), "ECDH_compute_key");
        }
    }

    void encrypt_key(const Sha256Hash& info)
    {
        const std::size_t ke_length = m_aes_key.size();
        static constexpr std::size_t km_length = 32;

        // derive ke and km from shared secret
        ByteBuffer kdp { info.octets.begin(), info.octets.end() };
        auto hashed_shared_secret = calculate_kdf2(&calculate_sha256_hash, shared_secret(), kdp, ke_length + km_length);
        assert(hashed_shared_secret.size() == ke_length + km_length);

        // encrypt symmetric key
        m_encrypted_key.resize(ke_length);
        std::uint8_t* ke = hashed_shared_secret.data();
        for (std::size_t i = 0; i < ke_length; ++i) {
            m_encrypted_key[i] = ke[i] ^ m_aes_key[i];
        }

        // generate authentication tag
        ByteBuffer km { std::next(hashed_shared_secret.begin(), ke_length), hashed_shared_secret.end() };
        assert(km.size() == km_length);
        m_authentication_tag = calculate_hmac_sha256(km, m_encrypted_key);
    }

private:
    OpenSslPointer<EC_KEY> m_ephemeral;
    PublicKey m_recipient;
    ByteBuffer m_shared_secret;
    ByteBuffer m_aes_key;
    ByteBuffer m_nonce;
    ByteBuffer m_encrypted_key;
    ByteBuffer m_authentication_tag;
};

} // namespace

OpenSslSecurityModule::OpenSslSecurityModule(std::shared_ptr<CredentialStorage> cred) : m_credential_storage(cred)
{
}

Sha256Hash OpenSslSecurityModule::calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha256Hash hash;
    SHA256(buffer, length, hash.octets.data());
    return hash;
}

Sha384Hash OpenSslSecurityModule::calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha384Hash hash;
    SHA384(buffer, length, hash.octets.data());
    return hash;
}

bool OpenSslSecurityModule::verify(const Sha256Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

bool OpenSslSecurityModule::verify(const Sha384Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

bool OpenSslSecurityModule::verify(const std::uint8_t* dbuf, std::size_t dlen, const Signature& signature,
    const PublicKey& pubkey)
{
    if (signature.type == KeyType::Unspecified || pubkey.type == KeyType::Unspecified) {
        return false;
    } else if (signature.type != pubkey.type) {
        return false;
    } else if (signature.s.empty() || signature.r.empty()) {
        return false;
    }

    OpenSslPointer<EC_KEY> osl_pubkey = make_ec_key(pubkey);
    OpenSslPointer<ECDSA_SIG> osl_sig { ECDSA_SIG_new() };
    BIGNUM* osl_r = BN_bin2bn(signature.r.data(), signature.r.size(), nullptr);
    BIGNUM* osl_s = BN_bin2bn(signature.s.data(), signature.s.size(), nullptr);
    if (!osl_r || !osl_s) {
        BN_free(osl_r); // BN_free(nullptr) is a no-op
        BN_free(osl_s);
        return false;
    }
    // ownership of big numbers is transfered by calling ECDSA_SIG_set0!
    openssl_result(ECDSA_SIG_set0(osl_sig.raw(), osl_r, osl_s), "set signature");
    return (ECDSA_do_verify(dbuf, dlen, osl_sig.raw(), osl_pubkey.raw()) == 1);
}

std::unique_ptr<SecurityModule::EciesContext> OpenSslSecurityModule::create_ecies_context(const PublicKey& receiver,
    const Sha256Hash& info)
{
    return std::unique_ptr<SecurityModule::EciesContext> { new OpenSslEciesContext { receiver, info } };
}

ByteBuffer OpenSslSecurityModule::generate_nonce(std::size_t length)
{
    ByteBuffer nonce;
    nonce.resize(length);
    openssl_result(RAND_bytes(nonce.data(), nonce.size()), "RAND_bytes");
    return nonce;
}

ByteBuffer OpenSslSecurityModule::calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data)
{
    return pki::calculate_hmac_sha256(key, data);
}

boost::optional<Signature> OpenSslSecurityModule::sign(const ByteBuffer& digest, const PublicKey& pubkey)
{
    boost::optional<PrivateKey> privkey = m_credential_storage->fetch(pubkey);
    if (privkey) {
        return sign(digest, *privkey);
    } else {
        return boost::none;
    }
}

boost::optional<Signature> OpenSslSecurityModule::sign(const ByteBuffer& digest, const PrivateKey& privkey)
{
    OpenSslPointer<EC_KEY> osl_key = make_ec_key(privkey);
    OpenSslPointer<ECDSA_SIG> osl_sig { ECDSA_do_sign(digest.data(), digest.size(), osl_key.raw()) };
    if (osl_sig.raw()) {
        const BIGNUM* osl_r = nullptr;
        const BIGNUM* osl_s = nullptr;
        ECDSA_SIG_get0(osl_sig.raw(), &osl_r, &osl_s);
        Signature sig;
        sig.type = privkey.type;
        sig.r.resize(BN_num_bytes(osl_r));
        BN_bn2bin(osl_r, sig.r.data());
        sig.s.resize(BN_num_bytes(osl_s));
        BN_bn2bin(osl_s, sig.s.data());
        return sig;
    } else {
        throw OpenSslException(ERR_get_error(), "ECDSA_do_sign");
    }

    return boost::none;
}

PublicKey OpenSslSecurityModule::create_key(KeyType type)
{
    // create key according to type
    OpenSslPointer<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(type)) };
    openssl_result(EC_KEY_generate_key(ec_key.raw()), "EC_KEY_generate_key");
    openssl_result(EC_KEY_check_key(ec_key.raw()), "EC_KEY_check_key");

    PublicKey pub_key = make_public_key(ec_key.raw());

    // bn_priv must not be freed, returns pointer to internal structure of key
    const BIGNUM* bn_priv = EC_KEY_get0_private_key(ec_key.raw());
    if (!bn_priv) {
        throw security::openssl::Exception();
    }

    PrivateKey priv_key;
    priv_key.type = type;
    priv_key.key.resize(BN_num_bytes(bn_priv));
    BN_bn2bin(bn_priv, priv_key.key.data());

    // store key pair in credential store
    m_credential_storage->store(pub_key, priv_key);
    return pub_key;
}

bool OpenSslSecurityModule::discard_key(const PublicKey& key)
{
    return m_credential_storage->discard(key);
}

} // namespace pki
} // namespace vanetza
