#pragma once
#include <cstddef>

namespace vanetza
{
namespace security
{

enum class KeyType
{
    NistP256, // also known as prime256v1
    BrainpoolP256r1,
    BrainpoolP384r1
};

/**
 * Length of private key in bytes
 * \param type key type
 * \param length in bytes
 */
std::size_t key_length(KeyType type);

} // namespace security
} // namespace vanetza
