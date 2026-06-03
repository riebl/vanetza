#pragma once

#include "credential_storage.hpp"
#include <filesystem>

namespace vanetza
{
namespace pki
{

class CredentialFilesystemStorage : public CredentialStorage
{
public:
    CredentialFilesystemStorage(const std::filesystem::path& root);

    void store(const PublicKey&, const PrivateKey&) override;
    boost::optional<PrivateKey> fetch(const PublicKey&) override;
    bool discard(const PublicKey&) override;
    CredentialNameRange list() const override;
    bool discard(const std::string& canonical_hex) override;
    bool contains(const std::string& canonical_hex) const override;

private:
    std::filesystem::path build_key_path(const PublicKey&);
    std::filesystem::path build_key_path(const std::string& canonical_hex) const;

    std::filesystem::path m_root;
};

} // namespace pki
} // namespace vanetza
