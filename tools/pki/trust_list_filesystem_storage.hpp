#pragma once

#include "trust_list_storage.hpp"
#include <filesystem>

namespace vanetza
{
namespace pki
{

class SecurityModule;

class TrustListFilesystemStorage : public TrustListStorage
{
public:
    TrustListFilesystemStorage(std::shared_ptr<SecurityModule>, const std::filesystem::path&);
    void store(const CertificateTrustList&) override;
    boost::optional<CertificateTrustList> fetch(const HashedId8&) const override;

protected:
    std::filesystem::path filename(const HashedId8&) const;

private:
    std::shared_ptr<SecurityModule> m_security;
    std::filesystem::path m_root;
};

} // namespace pki
} // namespace vanetza
