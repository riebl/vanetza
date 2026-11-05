#pragma once

#include "security_module.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Data-Encrypted.h>

namespace vanetza
{
namespace pki
{

// forward declarations
struct HashedId8;

class EncryptedData : public asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t>
{
public:
    using wrapper = asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t>;

    EncryptedData();
    void generate_ciphertext(CryptoProvider&, const security::Aes128Key&, const ByteBuffer& payload);
    void add_recipient_info(const HashedId8&, const EncryptedSymmetricKey&);
    const OCTET_STRING_t* get_nonce() const;
    const OCTET_STRING_t* get_ciphertext() const;

    /**
     * \brief Decrypt a PKI response that reuses the request's symmetric AES key.
     *
     * The AA/EA encrypts its response with the request's AES key referenced via pskRecipInfo
     * (TS 102 941 §6.2.3.3.2 for AT, §6.2.3.2.2 for EC).
     * \param key AES key of the request
     * \throws DecodingFailure if the ciphertext or pskRecipInfo is missing or decryption fails
     */
    ByteBuffer decrypt(CryptoProvider&, const security::Aes128Key& key) const;

    // Lower-level builders that mutate an EtsiTs103097Data-Encrypted value in-place
    static void init(asn1c_type& dest);
    static void set_aes_ccm_ciphertext(asn1c_type& dest, CryptoProvider&, const security::Aes128Key&,
        const ByteBuffer& plaintext);
    static void append_recipient_info(asn1c_type& dest, const EncryptedSymmetricKey&, const HashedId8& recipient);

private:
    bool has_psk_recipient() const;
};

/**
 * Encrypted request to a PKI authority and the AES key for decrypting its response
 *
 * The authority encrypts its response with the request's key referenced via pskRecipInfo
 * (TS 102 941 §6.2.3.2.2 for EC, §6.2.3.3.2 for AT), thus the requester keeps the key until then.
 */
struct EncryptedRequest
{
    EncryptedData message;
    security::Aes128Key key;
};

} // namespace pki
} // namespace vanetza
