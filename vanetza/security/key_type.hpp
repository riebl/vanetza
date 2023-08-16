#pragma once

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

} // namespace security
} // namespace vanetza
