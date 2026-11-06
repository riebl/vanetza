#include <vanetza/security/psa_error.hpp>
#include <vanetza/security/psa_wrapper.hpp>
#include <mbedtls/pk.h> // Mbed TLS API beyond PSA, see encode_uncompressed_point()
#include <mutex>

#ifndef MBEDTLS_PK_PARSE_EC_COMPRESSED
#   error "Mbed TLS cannot decompress public keys, enable MBEDTLS_PK_PARSE_EC_COMPRESSED"
#endif

namespace vanetza
{
namespace security
{
namespace psa
{

namespace
{

// Mbed TLS public key context freed at the end of its lifetime, see encode_uncompressed_point()
class PkContext
{
public:
    PkContext() { mbedtls_pk_init(&m_context); }
    PkContext(const PkContext&) = delete;
    PkContext& operator=(const PkContext&) = delete;
    ~PkContext() { mbedtls_pk_free(&m_context); }

    mbedtls_pk_context* get() { return &m_context; }

private:
    mbedtls_pk_context m_context;
};

} // namespace

psa_status_t initialize()
{
    static std::once_flag flag;
    static psa_status_t status = PSA_ERROR_BAD_STATE;
    std::call_once(flag, [] { status = psa_crypto_init(); });
    return status;
}

std::error_code initialization_error()
{
    const psa_status_t status = initialize();
    return status == PSA_SUCCESS ? std::error_code {} : make_psa_error(status, SecurityModuleError::ModuleFailure);
}

psa_ecc_family_t ecc_family(KeyType type)
{
    switch (type) {
        case KeyType::NistP256:
            return PSA_ECC_FAMILY_SECP_R1;
        case KeyType::BrainpoolP256r1:
        case KeyType::BrainpoolP384r1:
            return PSA_ECC_FAMILY_BRAINPOOL_P_R1;
        default:
            return 0;
    }
}

expected<ByteBuffer> encode_uncompressed_point(const PublicKey& key)
{
    if (key.compression == KeyCompression::NoCompression) {
        ByteBuffer point = encode_ec_point(key);
        if (point.empty()) {
            return make_error_code(SecurityModuleError::InvalidPublicKey);
        }
        return point;
    }

    const ByteBuffer key_info = encode_subject_public_key_info(key);
    if (key_info.empty()) {
        return make_error_code(SecurityModuleError::InvalidPublicKey);
    }

    PkContext pk;
    int result = mbedtls_pk_parse_public_key(pk.get(), key_info.data(), key_info.size());
    if (result == MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE) {
        return make_psa_error(result, SecurityModuleError::UnsupportedKeyType);
    } else if (result != 0) {
        return make_psa_error(result, SecurityModuleError::InvalidPublicKey);
    }

    // PSA exports the point decompressed by PK from a temporary key
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    result = mbedtls_pk_get_psa_attributes(pk.get(), PSA_KEY_USAGE_VERIFY_HASH, &attributes);
    if (result != 0) {
        return make_psa_error(result, SecurityModuleError::ModuleFailure);
    }
    Key decompressed;
    result = mbedtls_pk_import_into_psa(pk.get(), &attributes, decompressed.output());
    psa_reset_key_attributes(&attributes);
    if (result == PSA_ERROR_NOT_SUPPORTED) {
        return make_psa_error(result, SecurityModuleError::UnsupportedKeyType);
    } else if (result != 0) {
        return make_psa_error(result, SecurityModuleError::ModuleFailure);
    }

    ByteBuffer point(1 + 2 * key_length(key.type));
    std::size_t length = 0;
    const psa_status_t status = psa_export_public_key(decompressed.id(), point.data(), point.size(), &length);
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (length != point.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return point;
}

Key::~Key()
{
    psa_destroy_key(m_id);
}

} // namespace psa
} // namespace security
} // namespace vanetza
