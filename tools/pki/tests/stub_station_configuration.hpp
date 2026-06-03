#pragma once

#include "station_config.hpp"

namespace vanetza
{
namespace pki
{

// In-memory station configuration for unit tests.
class StubStationConfiguration : public StationConfiguration
{
public:
    std::string get_canonical_identifier() const override
    {
        return m_id;
    }

    void set_canonical_identifier(const std::string& s) override
    {
        m_id = s;
    }

    boost::optional<HashedId8> get_ec_identifier() const override
    {
        return m_ec;
    }

    void set_ec_identifier(const HashedId8& id) override
    {
        m_ec = id;
    }

    boost::optional<HashedId8> get_root_ca() const override
    {
        return m_root_ca;
    }

    void set_root_ca(const HashedId8& id) override
    {
        m_root_ca = id;
    }

private:
    std::string m_id;
    boost::optional<HashedId8> m_ec;
    boost::optional<HashedId8> m_root_ca;
};

} // namespace pki
} // namespace vanetza
