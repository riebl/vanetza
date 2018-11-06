#include <vanetza/security/length_coding.hpp>
#include <cassert>
#include <cmath>
#include <iterator>
#include <list>

namespace vanetza
{
namespace security
{

std::size_t count_leading_ones(uint8_t v)
{
    std::size_t count = 0;
    while ((v & 0x80) != 0) {
        v <<= 1;
        ++count;
    }
    return count;
}

std::size_t length_coding_size(std::uintmax_t length) {
    std::size_t size = 1;
    while ((length & ~0x7f) != 0) {
        // prefix enlongates by one additional leading "1" per shift
        length >>= 7; // shift by 7
        ++size;
    }
    return size;
}

ByteBuffer encode_length(std::uintmax_t length)
{
    static_assert(sizeof(std::uintmax_t) <= 8, "size of length type exceeds implementation capabilities");
    std::list<uint8_t> length_info;

    while (length != 0) {
        length_info.push_front(static_cast<uint8_t>(length));
        length >>= 8;
    }

    unsigned prefix_length = length_info.size();
    if (prefix_length == 0) {
        // Zero-size encoding
        length_info.push_back(0x00);
    }
    else {
        assert(prefix_length <= 8);
        uint8_t prefix_mask = ~((1 << (8 - prefix_length)) - 1);
        if ((length_info.front() & ~prefix_mask) != length_info.front()) {
            // additional byte needed for prefix
            length_info.push_front(prefix_mask);
        }
        else {
            // enough free bits available for prefix
            length_info.front() |= (prefix_mask << 1);
        }
        // Huge lengths have all bits set in leading prefix bytes
        length_info.insert(length_info.begin(), prefix_length / 8, 0xff);
    }

    return ByteBuffer(length_info.begin(), length_info.end());
}

std::tuple<ByteBuffer::const_iterator, std::uintmax_t> decode_length(const ByteBuffer& buffer)
{
    if (!buffer.empty()) {
        std::size_t additional_prefix = count_leading_ones(buffer.front());

        if (additional_prefix >= sizeof(std::uintmax_t)) {
            // encoded length is wider than uintmax_t, we cannot represent this number
            return std::make_tuple(buffer.begin(), 0);
        } else if (buffer.size() > additional_prefix) {
            uint8_t prefix_mask = (1 << (8 - additional_prefix)) - 1;
            std::uintmax_t length = buffer.front() & prefix_mask;
            for (std::size_t i = 1; i <= additional_prefix; ++i) {
                length <<= 8;
                length |= buffer[i];
            }

            auto start = buffer.begin();
            std::advance(start, additional_prefix + 1);
            return std::make_tuple(start, length);
        }
    }

    return std::make_tuple(buffer.end(), 0);
}

} // namespace security
} // namespace vanextza
