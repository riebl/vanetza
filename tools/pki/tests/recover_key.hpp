#pragma once

#include "asn1.hpp"
#include "certificate.hpp"
#include "keys.hpp"
#include "openssl.hpp"
#include "security_module.hpp"
#include <vanetza/asn1/security/EtsiTs103097Data-Encrypted.h>
#include <vanetza/security/ecies.hpp>
#include <openssl/ec.h>
#include <algorithm>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

/**
 * Recover the AES key of encrypted data like its recipient
 *
 * The recipient derives the ECIES shared secret from its private encryption key and the data's ephemeral key,
 * and recovers the AES key from it with the IEEE-validated security::encrypt_key.
 * \param data encrypted data addressed to the recipient's certificate
 * \param recipient_key private encryption key of the recipient
 * \param recipient_certificate certificate of the recipient
 * \return AES key of data
 * \throws std::runtime_error unless the AES key is encrypted for the recipient and decrypts the data's ciphertext
 */
inline security::Aes128Key recover_key(CryptoProvider& crypto,
    const Vanetza_Security_EtsiTs103097Data_Encrypted_85P0_t& data, const PrivateKey& recipient_key,
    const Certificate& recipient_certificate)
{
    if (!data.content || data.content->present != Vanetza_Security_Ieee1609Dot2Content_PR_encryptedData) {
        throw std::runtime_error("data is not encrypted");
    }
    const auto& encrypted_data = data.content->choice.encryptedData;
    const auto& recipients = encrypted_data.recipients;
    if (recipients.list.count != 1 ||
        recipients.list.array[0]->present != Vanetza_Security_RecipientInfo_PR_certRecipInfo) {
        throw std::runtime_error("data is not addressed to a single certificate");
    }
    const auto& recipient = recipients.list.array[0]->choice.certRecipInfo;
    if (!(recipient.recipientId == recipient_certificate.calculate_hashed_id8(crypto).octets)) {
        throw std::runtime_error("data is addressed to another certificate");
    }

    const Vanetza_Security_EciesP256EncryptedKey_t* encrypted_key = nullptr;
    if (recipient.encKey.present == Vanetza_Security_EncryptedDataEncryptionKey_PR_eciesNistP256) {
        encrypted_key = &recipient.encKey.choice.eciesNistP256;
    } else if (recipient.encKey.present == Vanetza_Security_EncryptedDataEncryptionKey_PR_eciesBrainpoolP256r1) {
        encrypted_key = &recipient.encKey.choice.eciesBrainpoolP256r1;
    } else {
        throw std::runtime_error("data has unsupported encrypted key");
    }

    PublicKey ephemeral;
    ephemeral.type = recipient_key.type;
    if (encrypted_key->v.present == Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0) {
        ephemeral.compression = KeyCompression::Y0;
        ephemeral.x = copy(encrypted_key->v.choice.compressed_y_0);
    } else if (encrypted_key->v.present == Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1) {
        ephemeral.compression = KeyCompression::Y1;
        ephemeral.x = copy(encrypted_key->v.choice.compressed_y_1);
    } else {
        throw std::runtime_error("data has uncompressed ephemeral key");
    }

    // equals the sender's shared secret from its ephemeral private key and the recipient's public key
    ByteBuffer shared_secret(security::key_length(recipient_key.type));
    if (ECDH_compute_key(shared_secret.data(), shared_secret.size(), make_ec_point(ephemeral).raw(),
            make_ec_key(recipient_key).raw(), nullptr) != static_cast<int>(shared_secret.size())) {
        throw std::runtime_error("data has invalid ephemeral key");
    }

    // encrypting an all-zero key reveals the key encryption mask
    const Sha256Hash info = calculate_sha256_hash(crypto, recipient_certificate);
    const EncryptedSymmetricKey mask =
        security::encrypt_key(crypto, ephemeral, create_byte_view(shared_secret), security::Aes128Key {}, info).value();
    if (encrypted_key->c.size != mask.wrapped_key.size()) {
        throw std::runtime_error("data has encrypted key of unexpected length");
    }
    security::Aes128Key key;
    for (std::size_t i = 0; i < key.octets.size(); ++i) {
        key.octets[i] = encrypted_key->c.buf[i] ^ mask.wrapped_key[i];
    }

    // authentication tag matches only if the key has been encrypted for the recipient
    const EncryptedSymmetricKey expected =
        security::encrypt_key(crypto, ephemeral, create_byte_view(shared_secret), key, info).value();
    if (!(encrypted_key->t == expected.authentication_tag.octets)) {
        throw std::runtime_error("data's key is not encrypted for the recipient");
    }

    if (encrypted_data.ciphertext.present != Vanetza_Security_SymmetricCiphertext_PR_aes128ccm) {
        throw std::runtime_error("data lacks AES-CCM ciphertext");
    }
    const auto& aes_ccm = encrypted_data.ciphertext.choice.aes128ccm;
    AesCcmCiphertext ciphertext;
    if (aes_ccm.nonce.size != ciphertext.nonce.size()) {
        throw std::runtime_error("data has AES-CCM nonce of unexpected length");
    }
    std::copy_n(aes_ccm.nonce.buf, ciphertext.nonce.size(), ciphertext.nonce.begin());
    ciphertext.ciphertext = copy(aes_ccm.ccmCiphertext);
    if (!crypto.decrypt_aes_ccm(key, ciphertext)) {
        throw std::runtime_error("data is not decryptable with its encrypted key");
    }
    return key;
}

} // namespace pki
} // namespace vanetza
