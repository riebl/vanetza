#pragma once

#include <psa/crypto.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace vanetza
{
namespace security
{
namespace psa
{

/**
 * Initialize PSA Crypto API once for all its users
 * \return status of the single initialization
 */
psa_status_t initialize();

/**
 * Calculate hash by PSA Crypto API
 * \param algo hash algorithm with digest length N
 * \throw std::runtime_error if calculation fails
 */
template<std::size_t N>
void calculate_hash(psa_algorithm_t algo, const std::uint8_t* data, std::size_t len,
    std::array<std::uint8_t, N>& digest)
{
    std::size_t digest_length = 0;
    if (initialize() != PSA_SUCCESS) {
        throw std::runtime_error("PSA crypto initialization failed");
    } else if (psa_hash_compute(algo, data, len, digest.data(), digest.size(), &digest_length) != PSA_SUCCESS) {
        throw std::runtime_error("PSA hash calculation failed");
    } else if (digest_length != digest.size()) {
        throw std::runtime_error("PSA hash calculation has unexpected length");
    }
}

/**
 * Volatile key destroyed at the end of its lifetime
 */
class Key
{
public:
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key();

    psa_key_id_t id() const { return m_id; }

    /**
     * Get destination for functions creating a key
     * \return pointer to key identifier
     */
    psa_key_id_t* output() { return &m_id; }

private:
    psa_key_id_t m_id = PSA_KEY_ID_NULL;
};

} // namespace psa
} // namespace security
} // namespace vanetza
