#ifndef BASIC_HEADER_HPP_8QS7WLG3
#define BASIC_HEADER_HPP_8QS7WLG3

#include <vanetza/common/bit_number.hpp>
#include <vanetza/geonet/lifetime.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/serialization.hpp>

namespace vanetza
{
namespace geonet
{

struct DataRequest;
struct ShbDataRequest;

enum class NextHeaderBasic : uint8_t
{
    ANY = 0, COMMON = 1, SECURED = 2
};

struct BasicHeader
{
    BasicHeader();
    BasicHeader(const MIB&);
    BasicHeader(const DataRequest&, const MIB&);
    BasicHeader(const ShbDataRequest&, const MIB&);

    static const std::size_t length_bytes = 3 + sizeof(Lifetime);

    BitNumber<unsigned, 4> version;
    NextHeaderBasic next_header; // 4 bit
    uint8_t reserved;
    Lifetime lifetime;
    uint8_t hop_limit;
};

void serialize(const BasicHeader&, OutputArchive&);
void deserialize(BasicHeader&, InputArchive&);

} // namespace geonet
} // namespace vanetza

#endif /* BASIC_HEADER_HPP_8QS7WLG3 */

