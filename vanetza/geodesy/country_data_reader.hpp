#pragma once
#include <vanetza/geodesy/country_polygon.hpp>
#include <vanetza/geodesy/m49_code.hpp>
#include <cstddef>
#include <cstdint>
#include <string>

namespace vanetza
{
namespace geodesy
{

class CountryReaderResult
{
public:
    static CountryReaderResult success(std::size_t pos)
    {
        return CountryReaderResult { pos };
    }

    static CountryReaderResult failure(std::string msg, std::size_t pos)
    {
        return CountryReaderResult { std::move(msg), pos };
    }

    bool ok() const { return m_success; }
    bool failed() const { return !ok(); }
    const std::string& message() const { return m_detail; }
    std::size_t position() const { return m_position; }

    CountryReaderResult& add_offset(std::size_t offset)
    {
        m_position += offset;
        return *this;
    }

private:
    CountryReaderResult(std::size_t pos) : m_position(pos) {}
    CountryReaderResult(std::string msg, std::size_t pos) :
        m_success(false), m_position(pos), m_detail(std::move(msg)) {}

    bool m_success = true;
    std::size_t m_position = 0;
    std::string m_detail;
};

namespace detail
{

/**
 * Version of the country data binary file format recognised by the reader.
 */
static constexpr uint16_t country_data_format_version = 1;

/**
 * Parse a single WKB geometry blob (Polygon or MultiPolygon) into a CountryPolygon.
 * Positions in the returned result are relative to the WKB data blob.
 * \param data pointer to WKB data
 * \param length size of WKB data in bytes
 * \param out parsed polygon (output)
 * \return ok on success, failure(msg, pos) on parse error
 */
CountryReaderResult parse_wkb(const uint8_t* data, std::size_t length, CountryPolygon& out);

uint16_t read_u16le(const uint8_t*);
uint32_t read_u32le(const uint8_t*);

} // namespace detail

/**
 * Parse a country data binary file (custom framing around OGC WKB payloads).
 *
 * File format: version (uint16 LE) | sequence of entries until EOF
 * Each entry: m49_code (uint16 LE) | wkb_size (uint32 LE) | wkb_data (wkb_size bytes, OGC WKB).
 *
 * Positions in the returned result are relative to the start of the input buffer.
 *
 * \param data pointer to binary data (may be nullptr if length is 0)
 * \param length size of data in bytes
 * \param fn callback invoked for each parsed entry: void(M49Code, CountryPolygon&&)
 * \return ok on success, failure(msg, pos) on parse error
 */
template<typename CallbackFn>
CountryReaderResult read_country_data(const uint8_t* data, std::size_t length, CallbackFn fn)
{
    if (length < sizeof(uint16_t)) {
        return CountryReaderResult::failure("truncated file header: missing version field", 0);
    }

    uint16_t version = detail::read_u16le(data);
    if (version != detail::country_data_format_version) {
        return CountryReaderResult::failure("unsupported country data format version", 0);
    }

    std::size_t offset = sizeof(uint16_t);
    const std::size_t entry_header_size = sizeof(uint16_t) + sizeof(uint32_t);

    while (offset < length) {
        if (length - offset < entry_header_size) {
            return CountryReaderResult::failure("truncated entry header", offset);
        }

        uint16_t m49 = detail::read_u16le(data + offset);
        offset += sizeof(uint16_t);

        uint32_t wkb_size = detail::read_u32le(data + offset);
        offset += sizeof(uint32_t);

        if (length - offset < wkb_size) {
            return CountryReaderResult::failure("invalid WKB payload size exceeding remaining data", offset);
        }

        CountryPolygon polygon;
        auto inner = detail::parse_wkb(data + offset, wkb_size, polygon);
        if (inner.failed()) {
            inner.add_offset(offset);
            return inner;
        }

        fn(M49Code(m49), std::move(polygon));
        offset += wkb_size;
    }

    return CountryReaderResult::success(offset);
}

} // namespace geodesy
} // namespace vanetza
