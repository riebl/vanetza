#pragma once

#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/security_module.hpp>

namespace vanetza
{
namespace security
{

class ScopedKeyPair
{
public:
    ScopedKeyPair(SecurityModule& sm, KeyType type) : m_security(&sm), m_public_key(sm.create_key(type))
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
            m_security->discard_key(m_public_key);
        }
    }

    const PublicKey& public_key() const
    {
        return m_public_key;
    }

    void commit()
    {
        // will no longer discard created key
        m_security = nullptr;
    }

private:
    SecurityModule* m_security = nullptr;
    PublicKey m_public_key;
};

} // namespace security
} // namespace vanetza
