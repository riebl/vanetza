#pragma once

#include "keys.hpp"
#include <boost/optional/optional.hpp>
#include <boost/range/any_range.hpp>
#include <string>

namespace vanetza
{
namespace pki
{

/// \brief Lazy, single-pass view over canonical-hex credential names.
using CredentialNameRange =
    boost::any_range<std::string, boost::single_pass_traversal_tag, std::string, std::ptrdiff_t>;

class CredentialStorage
{
public:
    virtual ~CredentialStorage() = default;
    virtual void store(const PublicKey&, const PrivateKey&) = 0;
    virtual boost::optional<PrivateKey> fetch(const PublicKey&) = 0;
    virtual bool discard(const PublicKey&) = 0;

    /// \brief Lazy iteration over the canonical-hex name of every stored credential.
    virtual CredentialNameRange list() const = 0;

    /// \brief Discard a credential by its canonical-hex name; returns true iff one was removed.
    virtual bool discard(const std::string& canonical_hex) = 0;

    /// \brief Existence check by canonical-hex name; cheap, no key parsing.
    virtual bool contains(const std::string& canonical_hex) const = 0;
};

/**
 * \brief RAII handle that discards a credential on destruction unless commit() was called.
 *
 * Use to bind a freshly generated key to the lifetime of a protocol step:
 * store now, drop the key if anything throws before the step succeeds.
 */
class ScopedCredential
{
public:
    ScopedCredential(CredentialStorage& storage, PublicKey pub) : m_storage(&storage), m_public_key(std::move(pub))
    {
    }

    ScopedCredential(CredentialStorage& storage, PublicKey pub, const PrivateKey& priv) : ScopedCredential(storage, pub)
    {
        m_storage->store(m_public_key, priv);
    }

    ~ScopedCredential()
    {
        if (m_storage) {
            m_storage->discard(m_public_key);
        }
    }

    // no copy
    ScopedCredential(const ScopedCredential&) = delete;
    ScopedCredential& operator=(const ScopedCredential&) = delete;
    // no move
    ScopedCredential(ScopedCredential&&) = delete;
    ScopedCredential& operator=(ScopedCredential&&) = delete;

    void commit()
    {
        m_storage = nullptr;
    }

private:
    CredentialStorage* m_storage = nullptr;
    PublicKey m_public_key;
};

} // namespace pki
} // namespace vanetza
