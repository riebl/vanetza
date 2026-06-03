#pragma once

#include "certificate_storage.hpp"
#include "credential_storage.hpp"
#include "crl_store.hpp"
#include "filesystem.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include "station_config.hpp"
#include "trust_list_storage.hpp"
#include <memory>

namespace vanetza
{
namespace pki
{

struct MainConfig
{
    std::filesystem::path config_path;
    std::filesystem::path data_path;
    std::string dc_url;
    HashedId8 root_ca_hid8;
    std::shared_ptr<StationConfiguration> station;
    std::shared_ptr<SecurityModule> security;
    std::shared_ptr<CertificateStorage> root_ca; // root CA certificates
    std::shared_ptr<CertificateStorage> enrolment_credentials; // station's EC certificates
    std::shared_ptr<CertificateStorage> tickets; // station's authorization tickets
    std::shared_ptr<CertificateStorage> tlm; // trust list manager certificates
    std::shared_ptr<CredentialStorage> credentials; // private keys
    std::shared_ptr<TrustListStorage> trust_lists;
    std::shared_ptr<CrlFilesystemStore> crl_store; // certificate revocation lists
};

boost::optional<std::string> lookup_dc_url(const std::filesystem::path& ectl_file, const HashedId8& root_ca);

} // namespace pki
} // namespace vanetza
