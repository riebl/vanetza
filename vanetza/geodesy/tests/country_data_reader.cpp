#include <vanetza/common/byte_order.hpp>
#include <vanetza/geodesy/country_data_reader.hpp>
#include <gtest/gtest.h>
#include <cstring>
#include <map>
#include <vector>

using namespace vanetza;
using namespace vanetza::geodesy;

namespace
{

template<ByteOrder Order, typename T>
void append(std::vector<uint8_t>& buf, T v)
{
    EndianType<T, Order> e = host_cast(v);
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

void append_u32be(std::vector<uint8_t>& buf, uint32_t v)
{
    append<ByteOrder::BigEndian>(buf, v);
}

void append_f64le(std::vector<uint8_t>& buf, double v)
{
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    append<ByteOrder::LittleEndian>(buf, bits);
}

void append_f64be(std::vector<uint8_t>& buf, double v)
{
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    append<ByteOrder::BigEndian>(buf, bits);
}

std::vector<uint8_t> make_wkb_polygon_le(const std::vector<std::pair<double, double>>& ring)
{
    std::vector<uint8_t> wkb;
    wkb.push_back(0x01); // little-endian
    append_u32le(wkb, 3); // type = Polygon
    append_u32le(wkb, 1); // num_rings = 1
    uint32_t num_points = static_cast<uint32_t>(ring.size()) + 1; // +1 for closing point
    append_u32le(wkb, num_points);
    for (const auto& p : ring) {
        append_f64le(wkb, p.first);  // lon
        append_f64le(wkb, p.second); // lat
    }
    append_f64le(wkb, ring.front().first);
    append_f64le(wkb, ring.front().second);
    return wkb;
}

std::vector<uint8_t> make_wkb_polygon_be(const std::vector<std::pair<double, double>>& ring)
{
    std::vector<uint8_t> wkb;
    wkb.push_back(0x00); // big-endian
    append_u32be(wkb, 3); // type = Polygon
    append_u32be(wkb, 1); // num_rings = 1
    uint32_t num_points = static_cast<uint32_t>(ring.size()) + 1;
    append_u32be(wkb, num_points);
    for (const auto& p : ring) {
        append_f64be(wkb, p.first);
        append_f64be(wkb, p.second);
    }
    append_f64be(wkb, ring.front().first);
    append_f64be(wkb, ring.front().second);
    return wkb;
}

std::vector<uint8_t> make_wkb_multipolygon_le(const std::vector<std::pair<double, double>>& ring)
{
    auto poly_wkb = make_wkb_polygon_le(ring);
    std::vector<uint8_t> wkb;
    wkb.push_back(0x01); // little-endian
    append_u32le(wkb, 6); // type = MultiPolygon
    append_u32le(wkb, 1); // num_polygons = 1
    wkb.insert(wkb.end(), poly_wkb.begin(), poly_wkb.end());
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

std::vector<uint8_t> make_file(std::initializer_list<std::vector<uint8_t>> entries)
{
    std::vector<uint8_t> buf;
    append_u16le(buf, vanetza::geodesy::detail::country_data_format_version);
    for (const auto& e : entries) {
        buf.insert(buf.end(), e.begin(), e.end());
    }
    return buf;
}

// A simple square polygon approximating Europe: (5,45) to (15,55)
const std::vector<std::pair<double, double>> square_europe = {
    {5.0, 45.0}, {15.0, 45.0}, {15.0, 55.0}, {5.0, 55.0}
};

// A simple square polygon approximating France: (-5,42) to (10,51)
const std::vector<std::pair<double, double>> square_france = {
    {-5.0, 42.0}, {10.0, 42.0}, {10.0, 51.0}, {-5.0, 51.0}
};

} // anonymous namespace

TEST(CountryDataReader, empty_input)
{
    auto result = read_country_data(nullptr, 0, [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
}

TEST(CountryDataReader, header_only)
{
    auto data = make_file({});

    std::map<uint16_t, CountryPolygon> result;
    auto r = read_country_data(data.data(), data.size(), [&](M49Code code, CountryPolygon&& poly) {
        result[code.value()] = std::move(poly);
    });
    EXPECT_TRUE(r.ok());
}

TEST(CountryDataReader, single_polygon_entry)
{
    auto wkb = make_wkb_polygon_le(square_europe);
    auto data = make_file({make_entry(276, wkb)});

    std::map<uint16_t, CountryPolygon> result;
    auto r = read_country_data(data.data(), data.size(), [&](M49Code code, CountryPolygon&& poly) {
        result[code.value()] = std::move(poly);
    });
    EXPECT_TRUE(r.ok());
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(1u, result.count(276));
}

TEST(CountryDataReader, multipolygon_entry)
{
    auto wkb = make_wkb_multipolygon_le(square_europe);
    auto data = make_file({make_entry(276, wkb)});

    std::map<uint16_t, CountryPolygon> result;
    auto r = read_country_data(data.data(), data.size(), [&](M49Code code, CountryPolygon&& poly) {
        result[code.value()] = std::move(poly);
    });
    EXPECT_TRUE(r.ok());
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(1u, result.count(276));
}

TEST(CountryDataReader, multiple_entries)
{
    auto wkb1 = make_wkb_polygon_le(square_europe);
    auto wkb2 = make_wkb_polygon_le(square_france);
    auto data = make_file({make_entry(276, wkb1), make_entry(250, wkb2)});

    std::map<uint16_t, CountryPolygon> result;
    auto r = read_country_data(data.data(), data.size(), [&](M49Code code, CountryPolygon&& poly) {
        result[code.value()] = std::move(poly);
    });
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(2u, result.size());
    EXPECT_EQ(1u, result.count(276));
    EXPECT_EQ(1u, result.count(250));
}

TEST(CountryDataReader, big_endian_wkb_payload)
{
    auto wkb = make_wkb_polygon_be(square_europe);
    auto data = make_file({make_entry(276, wkb)});

    std::map<uint16_t, CountryPolygon> result;
    auto r = read_country_data(data.data(), data.size(), [&](M49Code code, CountryPolygon&& poly) {
        result[code.value()] = std::move(poly);
    });
    EXPECT_TRUE(r.ok());
    ASSERT_EQ(1u, result.size());
    EXPECT_EQ(1u, result.count(276));
}

TEST(CountryDataReader, truncated_version_header)
{
    std::vector<uint8_t> data = {0x14}; // only 1 byte, not enough for version field
    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
}

TEST(CountryDataReader, unsupported_version)
{
    std::vector<uint8_t> data;
    append_u16le(data, vanetza::geodesy::detail::country_data_format_version + 1);

    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
}

TEST(CountryDataReader, truncated_entry_header)
{
    std::vector<uint8_t> data;
    append_u16le(data, vanetza::geodesy::detail::country_data_format_version);
    data.push_back(0x14); // one byte of an entry header, not enough

    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
}

TEST(CountryDataReader, truncated_wkb_payload)
{
    auto wkb = make_wkb_polygon_le(square_europe);
    auto data = make_file({make_entry(276, wkb)});
    // keep the version header + entry header intact but truncate halfway through the WKB
    data.resize(data.size() - wkb.size() / 2);

    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
    EXPECT_FALSE(result.message().empty());
}

TEST(CountryDataReader, wkb_size_exceeds_remaining)
{
    std::vector<uint8_t> data;
    append_u16le(data, vanetza::geodesy::detail::country_data_format_version);
    append_u16le(data, 276);
    append_u32le(data, 9999); // claims 9999 bytes of WKB
    data.push_back(0x01); // just 1 byte

    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
}

TEST(CountryDataReader, unsupported_geometry_type)
{
    std::vector<uint8_t> wkb;
    wkb.push_back(0x01); // little-endian
    append_u32le(wkb, 1); // type = Point (unsupported)
    append_f64le(wkb, 10.0);
    append_f64le(wkb, 50.0);
    auto data = make_file({make_entry(276, wkb)});

    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    EXPECT_TRUE(result.failed());
}

TEST(CountryDataReader, failure_reports_position)
{
    // "truncated entry header" — position is the offset of the partial entry (right after version).
    std::vector<uint8_t> data;
    append_u16le(data, vanetza::geodesy::detail::country_data_format_version);
    data.push_back(0x14); // partial entry header at offset 2

    auto result = read_country_data(data.data(), data.size(), [](M49Code, CountryPolygon&&) {});
    ASSERT_TRUE(result.failed());
    EXPECT_EQ(sizeof(uint16_t), result.position());
}
