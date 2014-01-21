#ifndef SERIALIZATION_BUFFER_HPP_KWLZAXD3
#define SERIALIZATION_BUFFER_HPP_KWLZAXD3

#include <vanetza/geonet/serialization.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/byte_buffer_source.hpp>
#include <boost/iostreams/stream_buffer.hpp>

namespace vanetza
{
namespace geonet
{

template<typename T>
void serialize_into_buffer(const T& t, ByteBuffer& buf)
{
    byte_buffer_sink sink(buf);
    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream, boost::archive::no_header);
    serialize(t, ar);
}

template<typename T>
void deserialize_from_buffer(T& t, const ByteBuffer& buf)
{
    byte_buffer_source source(buf);
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream, boost::archive::no_header);
    deserialize(t, ar);
}

template<typename T>
void deserialize_from_range(T& t, typename byte_buffer_source::range range)
{
    byte_buffer_source source(range);
    boost::iostreams::stream_buffer<byte_buffer_source> stream(source);
    InputArchive ar(stream, boost::archive::no_header);
    deserialize(t, ar);
}

} // namespace geonet
} // namespace vanetza

#endif /* SERIALIZATION_BUFFER_HPP_KWLZAXD3 */

