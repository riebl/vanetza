#pragma once
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <vanetza/security/key_type.hpp>

namespace vanetza
{
namespace security
{

// forward declarations
class Backend;

namespace v3
{

// forward declarations
class CertificateView;

/**
 * Calculate message hash (combination of hashes).
 * 
 * This function creates the message hash according to IEEE 1609.2 cause 5.3.1.2.2
 * for verification type "certificate", i.e. not "self-signed" messages.
 * 
 * \param backend backend for cryptographic operations
 * \param algo hash algorithm
 * \param data message payload (data to be signed)
 * \param signing certificate used for signing
 * \return message digest
 */
ByteBuffer calculate_message_hash(Backend&, HashAlgorithm, const ByteBuffer& data, const CertificateView& signing);

/**
 * Determine the hash algorithm for a given key type.
 * \see IEEE 1609.2 clause 5.3.1.2.2 rule a)
 * \param key_type key type
 * \return suitable hash algorithm
 */
HashAlgorithm specified_hash_algorithm(KeyType key_type);

} // namespace v3
} // namespace security
} // namespace vanetza
