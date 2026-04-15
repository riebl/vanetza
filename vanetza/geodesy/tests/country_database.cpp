#include <vanetza/common/byte_order.hpp>
#include <vanetza/geodesy/country_data_reader.hpp>
#include <vanetza/geodesy/country_database.hpp>
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

using namespace vanetza;
using namespace vanetza::geodesy;
using vanetza::units::degree;

namespace
{

template<ByteOrder Order, typename T>
void append(std::vector<uint8_t>& buf, T v)
{
    EndianType<T, Order> e;
    e = host_cast(v);
    auto raw = e.get();
    const auto* p = reinterpret_cast<const uint8_t*>(&raw);
    buf.insert(buf.end(), p, p + sizeof(raw));
}

void append_u16le(std::vector<uint8_t>& buf, uint16_t v)
{
    append<ByteOrder::LittleEndian>(buf, v);
}

void append_u32le(std::vector<uint8_t>& buf, uint32_t v)
{
    append<ByteOrder::LittleEndian>(buf, v);
}

void append_f64le(std::vector<uint8_t>& buf, double v)
{
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    append<ByteOrder::LittleEndian>(buf, bits);
}

// Build WKB Polygon (LE) for a rectangle
std::vector<uint8_t> make_rect_wkb(double lon_min, double lat_min, double lon_max, double lat_max)
{
    std::vector<uint8_t> wkb;
    wkb.push_back(0x01); // LE
    append_u32le(wkb, 3); // Polygon
    append_u32le(wkb, 1); // 1 ring
    append_u32le(wkb, 5); // 5 points (closed)
    append_f64le(wkb, lon_min); append_f64le(wkb, lat_min);
    append_f64le(wkb, lon_max); append_f64le(wkb, lat_min);
    append_f64le(wkb, lon_max); append_f64le(wkb, lat_max);
    append_f64le(wkb, lon_min); append_f64le(wkb, lat_max);
    append_f64le(wkb, lon_min); append_f64le(wkb, lat_min);
    return wkb;
}

std::vector<uint8_t> make_entry(uint16_t m49, const std::vector<uint8_t>& wkb)
{
    std::vector<uint8_t> entry;
    append_u16le(entry, m49);
    append_u32le(entry, static_cast<uint32_t>(wkb.size()));
    entry.insert(entry.end(), wkb.begin(), wkb.end());
    return entry;
}

const uint16_t germany_m49 = 276;
const uint16_t france_m49 = 250;

std::vector<uint8_t> make_test_data()
{
    // Germany bounding box (rough): lon 5.9-15.0, lat 47.3-55.1
    auto de_wkb = make_rect_wkb(5.9, 47.3, 15.0, 55.1);
    // France bounding box (rough): lon -5.1-9.6, lat 42.3-51.1
    auto fr_wkb = make_rect_wkb(-5.1, 42.3, 9.6, 51.1);
    auto de_entry = make_entry(germany_m49, de_wkb);
    auto fr_entry = make_entry(france_m49, fr_wkb);
    std::vector<uint8_t> data;
    append_u16le(data, vanetza::geodesy::detail::country_data_format_version);
    data.insert(data.end(), de_entry.begin(), de_entry.end());
    data.insert(data.end(), fr_entry.begin(), fr_entry.end());
    return data;
}

} // anonymous namespace

TEST(CountryDatabase, initially_empty)
{
    CountryDatabase db;
    EXPECT_TRUE(db.empty());
}

TEST(CountryDatabase, load_from_buffer)
{
    auto data = make_test_data();
    CountryDatabase db;
    EXPECT_TRUE(db.load(data.data(), data.size()));
    EXPECT_FALSE(db.empty());
}

TEST(CountryDatabase, berlin_inside_germany)
{
    auto data = make_test_data();
    CountryDatabase db;
    ASSERT_TRUE(db.load(data.data(), data.size()));

    GeodeticPosition berlin(52.52 * degree, 13.405 * degree);
    EXPECT_TRUE(db.is_inside(M49Code(germany_m49), berlin));
}

TEST(CountryDatabase, paris_inside_france)
{
    auto data = make_test_data();
    CountryDatabase db;
    ASSERT_TRUE(db.load(data.data(), data.size()));

    GeodeticPosition paris(48.8566 * degree, 2.3522 * degree);
    EXPECT_TRUE(db.is_inside(M49Code(france_m49), paris));
}

TEST(CountryDatabase, berlin_not_in_france)
{
    auto data = make_test_data();
    CountryDatabase db;
    ASSERT_TRUE(db.load(data.data(), data.size()));

    GeodeticPosition berlin(52.52 * degree, 13.405 * degree);
    EXPECT_FALSE(db.is_inside(M49Code(france_m49), berlin));
}

TEST(CountryDatabase, mid_atlantic_in_no_country)
{
    auto data = make_test_data();
    CountryDatabase db;
    ASSERT_TRUE(db.load(data.data(), data.size()));

    GeodeticPosition ocean(40.0 * degree, -30.0 * degree);
    EXPECT_FALSE(db.is_inside(M49Code(germany_m49), ocean));
    EXPECT_FALSE(db.is_inside(M49Code(france_m49), ocean));
}

TEST(CountryDatabase, unknown_country_code)
{
    auto data = make_test_data();
    CountryDatabase db;
    ASSERT_TRUE(db.load(data.data(), data.size()));

    GeodeticPosition berlin(52.52 * degree, 13.405 * degree);
    EXPECT_FALSE(db.is_inside(M49Code(999), berlin));
}

TEST(CountryDatabase, load_invalid_data)
{
    std::vector<uint8_t> bad_data = {0x14};
    CountryDatabase db;
    std::string error;
    EXPECT_FALSE(db.load(bad_data.data(), bad_data.size(), &error));
    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(db.empty());
}

#ifdef VANETZA_WITH_EMBEDDED_COUNTRY_DATA

TEST(CountryDatabase, embedded_not_empty)
{
    auto db = CountryDatabase::embedded();
    EXPECT_FALSE(db.empty());
}

TEST(CountryDatabase, embedded_ingolstadt_in_germany)
{
    auto db = CountryDatabase::embedded();
    // Ingolstadt, Germany
    GeodeticPosition ingolstadt(48.7665 * degree, 11.4258 * degree);
    EXPECT_TRUE(db.is_inside(M49Code(germany_m49), ingolstadt));
}

TEST(CountryDatabase, embedded_etsi_hq_in_france)
{
    auto db = CountryDatabase::embedded();
    // ETSI headquarters, Sophia Antipolis, France
    GeodeticPosition etsi_hq(43.6244 * degree, 7.0494 * degree);
    EXPECT_TRUE(db.is_inside(M49Code(france_m49), etsi_hq));
}

#endif // VANETZA_WITH_EMBEDDED_COUNTRY_DATA
