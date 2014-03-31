#include "byte_buffer_convertible.hpp"

namespace vanetza
{
namespace convertible
{

std::unique_ptr<byte_buffer> byte_buffer::duplicate() const
{
    ByteBuffer duplicate;
    this->convert(duplicate);
    std::unique_ptr<byte_buffer> result {
        new byte_buffer_impl<ByteBuffer&&>(std::move(duplicate))
    };
    return result;
}

} // namespace convertible


{
}

} // namespace vanetza

