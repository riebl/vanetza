#include <vanetza/geodesy/country_database.hpp>
#include <vanetza/geodesy/country_data_reader.hpp>
#include <boost/geometry/algorithms/within.hpp>
#include <boost/units/quantity.hpp>
#include <fstream>
#include <iterator>
#include <vector>

#ifdef VANETZA_WITH_EMBEDDED_COUNTRY_DATA
#include <vanetza/common/byte_view.hpp>
namespace vanetza { namespace geodesy { namespace country { vanetza::byte_view_range embedded(); } } }
#endif

namespace vanetza
{
namespace geodesy
{

CountryDatabase CountryDatabase::embedded(std::string* error)
{
    CountryDatabase db;
#ifdef VANETZA_WITH_EMBEDDED_COUNTRY_DATA
    auto view = country::embedded();
    db.load(view.data(), view.size(), error);
#else
    if (error) {
        *error = "embedded country data not available";
    }
#endif
    return db;
}

bool CountryDatabase::load(const std::string& path, std::string* error)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        if (error) {
            *error = "cannot open file: " + path;
        }
        return false;
    }

    std::vector<uint8_t> data { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
    return load(data.data(), data.size(), error);
}

bool CountryDatabase::load(const uint8_t* data, std::size_t length, std::string* error)
{
    m_countries.clear();

    auto result = read_country_data(data, length,
        [this](M49Code code, CountryPolygon&& polygon) {
            m_countries.emplace(code, std::move(polygon));
        });

    if (result.failed()) {
        if (error) {
            *error = result.message() + " at offset " + std::to_string(result.position());
        }
        m_countries.clear();
        return false;
    }

    return true;
}

bool CountryDatabase::is_inside(M49Code country, const GeodeticPosition& position) const
{
    auto it = m_countries.find(country);
    if (it == m_countries.end()) {
        return false;
    }

    country::Point point(position.longitude / units::degree, position.latitude / units::degree);
    return boost::geometry::within(point, it->second);
}

bool CountryDatabase::empty() const
{
    return m_countries.empty();
}

} // namespace geodesy
} // namespace vanetza
