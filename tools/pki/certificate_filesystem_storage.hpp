#pragma once

#include "certificate_storage.hpp"
#include <filesystem>
#include <memory>
#include <string>

namespace vanetza
{
namespace pki
{

class SecurityModule;

class CertificateFilesystemStorage : public CertificateStorage
{
public:
    CertificateFilesystemStorage(std::shared_ptr<SecurityModule>, const std::filesystem::path&,
        std::string extension = ".oer");
    boost::optional<Certificate> fetch(const HashedId8&) const override;
    void store(const Certificate&) override;
    bool erase(const HashedId8&) override;
    HashedId8Range list() const override;

protected:
    std::filesystem::path filename(const HashedId8&) const;

private:
    std::shared_ptr<SecurityModule> m_security;
    std::filesystem::path m_root;
    std::string m_extension;
};

} // namespace pki
} // namespace vanetza
