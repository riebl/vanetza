#pragma once
#include <vanetza/geodesy/country_polygon.hpp>
#include <vanetza/geodesy/m49_code.hpp>
#include <vanetza/geodesy/position.hpp>
#include <cstddef>
#include <string>
#include <unordered_map>

namespace vanetza
{
namespace geodesy
{

class CountryDatabase
{
public:
    /**
     * Create a CountryDatabase from embedded country data.
     * Only available when built with VANETZA_WITH_EMBEDDED_COUNTRY_DATA.
     * \param[out] error optional error message
     * \return loaded database, or empty database on failure
     */
    static CountryDatabase embedded(std::string* error = nullptr);

    /**
     * Load country data from a file.
     * \param[in] path path to the binary country data file
     * \param[out] error optional error message
     * \return true on success
     */
    bool load(const std::string& path, std::string* error = nullptr);

    /**
     * Load country data from a memory buffer.
     * \param[in] data pointer to binary data
     * \param[in] length size of data in bytes
     * \param[out] error optional error message
     * \return true on success
     */
    bool load(const uint8_t* data, std::size_t length, std::string* error = nullptr);

    /**
     * Check if a geodetic position lies within a country.
     * \param country M.49 country code
     * \param position geodetic position to check
     * \return true if position is inside the country's boundaries
     */
    bool is_inside(M49Code country, const GeodeticPosition& position) const;

    /**
     * Check if the database contains any country data.
     * \return true if no countries are loaded
     */
    bool empty() const;

private:
    std::unordered_map<M49Code, CountryPolygon> m_countries;
};

} // namespace geodesy
} // namespace vanetza
