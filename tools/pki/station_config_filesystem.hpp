#pragma once

#include "filesystem.hpp"
#include "station_config.hpp"

namespace vanetza
{
namespace pki
{

class StationConfigurationFilesystem : public StationConfiguration
{
public:
    StationConfigurationFilesystem(const std::filesystem::path&);

    std::string get_canonical_identifier() const override;
    void set_canonical_identifier(const std::string&) override;

    boost::optional<HashedId8> get_ec_identifier() const override;
    void set_ec_identifier(const HashedId8&) override;

    boost::optional<HashedId8> get_root_ca() const override;
    void set_root_ca(const HashedId8&) override;

protected:
    boost::optional<HashedId8> get_hid8(const std::filesystem::path&) const;
    void set_hid8(const std::filesystem::path&, const HashedId8&);

private:
    std::filesystem::path m_root;
};

} // namespace pki
} // namespace vanetza
