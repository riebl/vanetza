#pragma once

#include <vanetza/common/expected.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/optional/optional.hpp>
#include <string>
#include <system_error>
#include <utility>

namespace vanetza
{
namespace security
{

class CredentialVisitor
{
public:
    virtual ~CredentialVisitor() = default;

    /// \brief Visit a stored credential by its canonical-hex name, see canonical_hexstring.
    virtual void visit(const std::string& canonical_hex) = 0;
};

/**
 * \brief Permanent storage of private keys looked up by their public keys.
 *
 * Storing, fetching and discarding by public key is mandatory,
 * housekeeping by canonical-hex name is optional.
 */
class CredentialStorage
{
public:
    virtual ~CredentialStorage() = default;
    virtual void store(const PublicKey&, const PrivateKey&) = 0;
    virtual boost::optional<PrivateKey> fetch(const PublicKey&) = 0;
    virtual bool discard(const PublicKey&) = 0;

    /// \brief Visit the canonical-hex name of every stored credential; visitor must not modify this storage.
    /// \return error, std::errc::operation_not_supported unless implemented
    virtual std::error_code visit(CredentialVisitor& visitor) const;

    /// \brief Discard a credential by its canonical-hex name; returns true iff one was removed.
    /// \return result or error, std::errc::operation_not_supported unless implemented
    virtual expected<bool> discard(const std::string& canonical_hex);

    /// \brief Existence check by canonical-hex name; cheap, no key parsing.
    /// \return result or error, std::errc::operation_not_supported unless implemented
    virtual expected<bool> contains(const std::string& canonical_hex) const;
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

} // namespace security
} // namespace vanetza
