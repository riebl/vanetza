#include "station_config_filesystem.hpp"
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace vanetza
{
namespace pki
{

namespace
{

// Write text to a config file; on a write error remove the half-written file so a later
// read sees a clean "unset" state rather than a corrupt one.
void write_config(const std::filesystem::path& path, const std::string& content)
{
    std::ofstream ofs(path);
    ofs << content;
    ofs.flush();
    if (!ofs) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        throw std::runtime_error("could not write station config file " + path.string());
    }
}

} // namespace

StationConfigurationFilesystem::StationConfigurationFilesystem(const std::filesystem::path& root) : m_root(root)
{
    std::filesystem::create_directories(m_root);
}

std::string StationConfigurationFilesystem::get_canonical_identifier() const
{
    std::ifstream ifs(m_root / "identifier");
    std::string identifier;
    std::getline(ifs, identifier);
    return identifier;
}

void StationConfigurationFilesystem::set_canonical_identifier(const std::string& identifier)
{
    write_config(m_root / "identifier", identifier);
}

boost::optional<HashedId8> StationConfigurationFilesystem::get_ec_identifier() const
{
    return get_hid8(m_root / "ec.hid8");
}

void StationConfigurationFilesystem::set_ec_identifier(const HashedId8& id)
{
    set_hid8(m_root / "ec.hid8", id);
}

boost::optional<HashedId8> StationConfigurationFilesystem::get_root_ca() const
{
    return get_hid8(m_root / "rootca.hid8");
}

void StationConfigurationFilesystem::set_root_ca(const HashedId8& id)
{
    set_hid8(m_root / "rootca.hid8", id);
}

boost::optional<HashedId8> StationConfigurationFilesystem::get_hid8(const std::filesystem::path& path) const
{
    std::ifstream ifs(path);
    std::string hex;
    std::getline(ifs, hex);
    return HashedId8::from_hexstring(hex);
}

void StationConfigurationFilesystem::set_hid8(const std::filesystem::path& path, const HashedId8& id)
{
    write_config(path, hexstring(id));
}

} // namespace pki
} // namespace vanetza
