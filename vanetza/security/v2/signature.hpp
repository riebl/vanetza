#ifndef SIGNATURE_HPP_ZWPLNDVE
#define SIGNATURE_HPP_ZWPLNDVE

#include <vanetza/security/signature.hpp>
#include <vanetza/security/v2/ecc_point.hpp>
#include <vanetza/security/v2/public_key.hpp>
#include <vanetza/security/v2/serialization.hpp>
#include <boost/optional/optional.hpp>
#include <boost/variant/variant.hpp>
#include <future>

namespace vanetza
{
namespace security
{
namespace v2
{

struct Signature {
    SomeEcdsaSignature some_ecdsa;

    Signature() = default;

    Signature(EcdsaSignature&& sig) : some_ecdsa(std::move(sig)) {}
    Signature& operator=(EcdsaSignature&& sig) { some_ecdsa = std::move(sig); return *this; }

    Signature(const EcdsaSignature& sig) : some_ecdsa(sig) {}
    Signature& operator=(const EcdsaSignature& sig) { some_ecdsa = sig; return *this; }

    Signature(EcdsaSignatureFuture&& sig) : some_ecdsa(std::move(sig)) {}
    Signature& operator=(EcdsaSignatureFuture&& sig) { some_ecdsa = std::move(sig); return *this; }

    Signature(SomeEcdsaSignature&& some) : some_ecdsa(std::move(some)) {}
    Signature& operator=(SomeEcdsaSignature&& some) { this->some_ecdsa = std::move(some); return *this; }
};

/**
 * brief Determines PublicKeyAlgorithm of a given Signature
 * \param signature
 * \return PublicKeyAlgorithm
 */
PublicKeyAlgorithm get_type(const Signature&);

/**
 * \brief Calculates size of a EcdsaSignature
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const EcdsaSignature&);

/**
 * \brief Calculates size of a EcdsaSignatureFuture
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const EcdsaSignatureFuture&);

/**
 * \brief Calculates size of a Signature
 * \param signature
 * \return number of octets needed for serialization
 */
size_t get_size(const Signature&);

/**
 * \brief Serializes a signature into a binary archive
 * \param ar to serialize in
 * \param signature
 */
void serialize(OutputArchive&, const Signature&);
void serialize(OutputArchive&, const EcdsaSignature&);
void serialize(OutputArchive&, const EcdsaSignatureFuture&);

/**
 * \brief Deserializes an EcdsaSignature from a binary archive
 *  Requires PublicKeyAlgorithm for determining the signature size
 * \param ar with a serialized EcdsaSignature at the beginning
 * \param signature to deserialize
 * \param public_key_algorithm to determine the size of the signature
 * \return size of the deserialized EcdsaSignature
 */
size_t deserialize(InputArchive&, EcdsaSignature&, const PublicKeyAlgorithm&);

/**
 * \brief Deserializes a Signature from a binary archive
 * \param ar with a serialized Signature at the beginning
 * \param signature to deserialize
 * \return size of the deserialized Signature
 */
size_t deserialize(InputArchive&, Signature&);

/**
 * Try to extract ECDSA signature from signature variant
 * \param sig Signature variant (of some type)
 * \return ECDSA signature (optionally)
 */
boost::optional<EcdsaSignature> extract_ecdsa_signature(const Signature& sig);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* SIGNATURE_HPP_ZWPLNDVE */
