#include "encrypted_data.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include "signed_builder.hpp"
#include <algorithm>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

namespace
{

const Vanetza_Security_AesCcmCiphertext_t*
get_aes_ccm_ciphertext(const Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t& dest)
{
    if (dest.content && dest.content->present == Vanetza_Security_Ieee1609Dot2Content_PR_encryptedData) {
        const auto& enc = dest.content->choice.encryptedData;
        if (enc.ciphertext.present == Vanetza_Security_SymmetricCiphertext_PR_aes128ccm) {
            return &enc.ciphertext.choice.aes128ccm;
        }
    }
    return nullptr;
}

} // namespace

void EncryptedData::init(asn1c_type& dest)
{
    dest.protocolVersion = ieee1609dot2_protocol_version;
    dest.content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
    dest.content->present = Vanetza_Security_Ieee1609Dot2Content_PR_encryptedData;
}

void EncryptedData::set_aes_ccm_ciphertext(asn1c_type& dest, CryptoProvider& crypto,
    const security::Aes128Key& key, const ByteBuffer& plaintext)
{
    expected<AesCcmCiphertext> encrypted = crypto.encrypt_aes_ccm(key, plaintext);
    if (!encrypted) {
        throw std::runtime_error("encryption failed: " + encrypted.error().message());
    }
    auto& aes = dest.content->choice.encryptedData.ciphertext;
    aes.present = Vanetza_Security_SymmetricCiphertext_PR_aes128ccm;
    copy(encrypted->nonce, aes.choice.aes128ccm.nonce);
    copy(encrypted->ciphertext, aes.choice.aes128ccm.ccmCiphertext);
}

void EncryptedData::append_recipient_info(asn1c_type& dest, const EncryptedSymmetricKey& key, const HashedId8& cert)
{
    auto recipient = asn1::allocate<Vanetza_Security_RecipientInfo_t>();
    asn_sequence_add(&dest.content->choice.encryptedData.recipients.list, recipient);
    recipient->present = Vanetza_Security_RecipientInfo_PR_certRecipInfo;
    OCTET_STRING_fromBuf(&recipient->choice.certRecipInfo.recipientId,
        reinterpret_cast<const char*>(cert.octets.data()), cert.octets.size());

    Vanetza_Security_EncryptedDataEncryptionKey_t& enckey = recipient->choice.certRecipInfo.encKey;
    switch (key.public_key.type) {
        case KeyType::NistP256:
            enckey.present = Vanetza_Security_EncryptedDataEncryptionKey_PR_eciesNistP256;
            fill_curve_point(key.public_key, enckey.choice.eciesNistP256.v);
            copy(key.authentication_tag.octets, enckey.choice.eciesNistP256.t);
            copy(key.wrapped_key, enckey.choice.eciesNistP256.c);
            break;
        case KeyType::BrainpoolP256r1:
            enckey.present = Vanetza_Security_EncryptedDataEncryptionKey_PR_eciesBrainpoolP256r1;
            fill_curve_point(key.public_key, enckey.choice.eciesBrainpoolP256r1.v);
            copy(key.authentication_tag.octets, enckey.choice.eciesBrainpoolP256r1.t);
            copy(key.wrapped_key, enckey.choice.eciesBrainpoolP256r1.c);
            break;
        default:
            throw std::runtime_error("unsupported encryption key type");
            break;
    }
}

EncryptedData::EncryptedData() : wrapper(asn_DEF_Vanetza_Security_EtsiTs103097Data_Encrypted_85P0)
{
    init(*m_struct);
}

void EncryptedData::generate_ciphertext(CryptoProvider& crypto, const security::Aes128Key& key,
    const ByteBuffer& plaintext)
{
    set_aes_ccm_ciphertext(*m_struct, crypto, key, plaintext);
}

void EncryptedData::add_recipient_info(const HashedId8& cert, const EncryptedSymmetricKey& key)
{
    append_recipient_info(*m_struct, key, cert);
}

const OCTET_STRING_t* EncryptedData::get_nonce() const
{
    auto aes_ccm = get_aes_ccm_ciphertext(*m_struct);
    return aes_ccm ? &aes_ccm->nonce : nullptr;
}

const OCTET_STRING_t* EncryptedData::get_ciphertext() const
{
    auto aes_ccm = get_aes_ccm_ciphertext(*m_struct);
    return aes_ccm ? &aes_ccm->ccmCiphertext : nullptr;
}

bool EncryptedData::has_psk_recipient() const
{
    const auto& recipients = m_struct->content->choice.encryptedData.recipients;
    for (int i = 0; i < recipients.list.count; ++i) {
        const Vanetza_Security_RecipientInfo_t* recipient = recipients.list.array[i];
        if (recipient && recipient->present == Vanetza_Security_RecipientInfo_PR_pskRecipInfo) {
            return true;
        }
    }
    return false;
}

ByteBuffer EncryptedData::decrypt(CryptoProvider& crypto, const security::Aes128Key& key) const
{
    auto aes_ccm = get_aes_ccm_ciphertext(*m_struct);
    if (!aes_ccm) {
        throw DecodingFailure("missing AES CCM ciphertext");
    }
    // A PKI response reuses the request's symmetric key, referenced via pskRecipInfo.
    if (!has_psk_recipient()) {
        throw DecodingFailure("encrypted PKI response lacks expected pskRecipInfo recipient");
    }

    AesCcmCiphertext ciphertext;
    if (aes_ccm->nonce.size != ciphertext.nonce.size()) {
        throw DecodingFailure("AES CCM nonce of unexpected length");
    }
    std::copy_n(aes_ccm->nonce.buf, ciphertext.nonce.size(), ciphertext.nonce.begin());
    ciphertext.ciphertext = copy(aes_ccm->ccmCiphertext);

    expected<ByteBuffer> plaintext = crypto.decrypt_aes_ccm(key, ciphertext);
    if (!plaintext) {
        throw DecodingFailure("encrypted PKI response: " + plaintext.error().message());
    }
    return std::move(*plaintext);
}

} // namespace pki
} // namespace vanetza
