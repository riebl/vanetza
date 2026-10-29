#pragma once

#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/security_module.hpp>
#include <utility>

namespace vanetza
{
namespace security
{

/**
 * Discards a key pair of a SecurityModule at end of scope unless committed
 */
class ScopedKeyPair
{
public:
    ScopedKeyPair(SecurityModule& sm, KeyReference key) : m_security(&sm), m_key(std::move(key))
    {
    }

    // no copy
    ScopedKeyPair(const ScopedKeyPair&) = delete;
    ScopedKeyPair& operator=(const ScopedKeyPair&) = delete;
    // no move
    ScopedKeyPair(ScopedKeyPair&&) = delete;
    ScopedKeyPair& operator=(ScopedKeyPair&&) = delete;

    ~ScopedKeyPair()
    {
        if (m_security) {
            m_security->discard_key(m_key);
        }
    }

    const KeyReference& reference() const
    {
        return m_key;
    }

    void commit()
    {
        // will no longer discard created key
        m_security = nullptr;
    }

private:
    SecurityModule* m_security = nullptr;
    KeyReference m_key;
};

} // namespace security
} // namespace vanetza
