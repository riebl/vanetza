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
class SecurityModule;

class EncryptedData : public asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t>
{
public:
    using wrapper = asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t>;

    EncryptedData(std::shared_ptr<SecurityModule::EciesContext> ecies);
    void generate_ciphertext(const ByteBuffer& payload);
    void add_recipient_info(const HashedId8&);
    const OCTET_STRING_t* get_nonce() const;
    const OCTET_STRING_t* get_ciphertext() const;

    /**
     * \brief Decrypt a PKI response that reuses the request's symmetric AES key.
     *
     * Call on the same EncryptedData instance that built the request, after
     * decode()-ing the response body into it. The AA/EA encrypts its response
     * with the request's AES key referenced via pskRecipInfo
     * (TS 102 941 §6.2.3.3.2 for AT, §6.2.3.2.2 for EC).
     * \throws DecodingFailure if the ciphertext or pskRecipInfo is missing
     */
    ByteBuffer decrypt();

    // Lower-level builders that mutate an EtsiTs103097Data-Encrypted value in-place
    static void init(asn1c_type& dest);
    static void set_aes_ccm_ciphertext(asn1c_type& dest, SecurityModule::EciesContext& ecies,
        const ByteBuffer& plaintext);
    static void append_recipient_info(asn1c_type& dest, const SecurityModule::EciesContext& ecies,
        const HashedId8& recipient);

private:
    bool has_psk_recipient() const;
    std::shared_ptr<SecurityModule::EciesContext> m_ecies;
};

} // namespace pki
} // namespace vanetza