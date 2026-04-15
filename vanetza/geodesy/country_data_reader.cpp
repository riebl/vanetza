#include <vanetza/common/byte_order.hpp>
#include <vanetza/geodesy/country_data_reader.hpp>
#include <cstring>

namespace vanetza
{
namespace geodesy
{
namespace detail
{

uint16_t read_u16le(const uint8_t* p)
{
    uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return endian_cast<ByteOrder::LittleEndian>(v).host();
}

uint32_t read_u32le(const uint8_t* p)
{
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return endian_cast<ByteOrder::LittleEndian>(v).host();
}

namespace
{

static constexpr std::size_t wkb_header_length = 5; /*< byte order (1) and type (4) */
static constexpr std::size_t wkb_count_length = 4; /*< counters are uint32_t (4) */
static constexpr std::uint32_t wkb_polygon_type = 3;
static constexpr std::uint32_t wkb_multipolygon_type = 6;

uint32_t read_u32(const uint8_t* p, bool little_endian)
{
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return little_endian
        ? endian_cast<ByteOrder::LittleEndian>(v).host()
        : endian_cast<ByteOrder::BigEndian>(v).host();
}

double read_f64(const uint8_t* p, bool little_endian)
{
    uint64_t bits;
    std::memcpy(&bits, p, sizeof(bits));
    bits = little_endian
        ? endian_cast<ByteOrder::LittleEndian>(bits).host()
        : endian_cast<ByteOrder::BigEndian>(bits).host();
    double v;
    std::memcpy(&v, &bits, sizeof(v));
    return v;
}

// Parse a WKB Polygon body (after byte-order and type fields).
// On success, `consumed` receives the number of bytes consumed from `data`.
// Positions in the returned result are relative to `data` (body start).
CountryReaderResult parse_polygon_body(const uint8_t* data, std::size_t length, bool le, country::Polygon& out)
{
    if (length < wkb_count_length) {
        return CountryReaderResult::failure("truncated polygon: missing ring count", 0);
    }

    uint32_t num_rings = read_u32(data, le);
    std::size_t offset = wkb_count_length;

    for (uint32_t r = 0; r < num_rings; ++r) {
        if (length - offset < wkb_count_length) {
            return CountryReaderResult::failure("truncated polygon: missing point count", offset);
        }

        uint32_t num_points = read_u32(data + offset, le);
        offset += wkb_count_length;

        std::size_t points_bytes = static_cast<std::size_t>(num_points) * 2 * sizeof(double);
        if (length - offset < points_bytes) {
            return CountryReaderResult::failure("truncated polygon: missinsg point data", offset);
        }

        country::Ring ring;
        ring.reserve(num_points);
        for (uint32_t i = 0; i < num_points; ++i) {
            double lon = read_f64(data + offset, le);
            offset += sizeof(double);
            double lat = read_f64(data + offset, le);
            offset += sizeof(double);
            ring.push_back(country::Point(lon, lat));
        }

        if (r == 0) {
            out.outer() = std::move(ring);
        } else {
            out.inners().push_back(std::move(ring));
        }
    }

    return CountryReaderResult::success(offset);
}

} // anonymous namespace

CountryReaderResult parse_wkb(const uint8_t* data, std::size_t length, CountryPolygon& out)
{
    if (length < wkb_header_length) {
        return CountryReaderResult::failure("WKB too short for header", 0);
    }

    bool le = (data[0] == 0x01);
    uint32_t type = read_u32(data + 1, le);

    if (type == wkb_polygon_type) {
        country::Polygon polygon;
        auto inner = parse_polygon_body(data + wkb_header_length, length - wkb_header_length, le, polygon);
        if (inner.ok()) {
            out.push_back(std::move(polygon));
        }
        return inner.add_offset(wkb_header_length);
    } else if (type == wkb_multipolygon_type) {
        if (length < wkb_header_length + wkb_count_length) {
            return CountryReaderResult::failure("truncated multi-polygon: missing polygon count", wkb_header_length);
        }
        uint32_t num_polygons = read_u32(data + wkb_header_length, le);
        std::size_t offset = wkb_header_length + wkb_count_length;

        for (uint32_t i = 0; i < num_polygons; ++i) {
            if (length - offset < wkb_header_length) {
                return CountryReaderResult::failure("truncated multi-polygon: missing polygon header", offset);
            }

            bool poly_le = (data[offset] == 0x01);
            uint32_t poly_type = read_u32(data + offset + 1, poly_le);            
            if (poly_type != wkb_polygon_type) {
                return CountryReaderResult::failure("unexpected geometry type inside multi-polygon", offset + 1);
            }
            offset += wkb_header_length;

            country::Polygon polygon;
            auto inner = parse_polygon_body(data + offset, length - offset, poly_le, polygon);
            if (inner.ok()) {
                out.push_back(std::move(polygon));
                offset += inner.position();
            } else {
                return inner.add_offset(offset);
            }
        }

        return CountryReaderResult::success(offset);
    } else {
        return CountryReaderResult::failure("unsupported WKB geometry type" , 1);
    }
}

} // namespace detail
} // namespace geodesy
} // namespace vanetza
