#ifndef MK2_DESCRIPTOR_HPP_
#define MK2_DESCRIPTOR_HPP_

#include <vanetza/common/byte_buffer.hpp>
#include <mk2mac-api-types.h>

namespace vanetza
{

ByteBuffer createMk2TxDescriptor(const tMK2TxDescriptor&);

} // namespace vanetza

#endif // MK2_DESCRIPTOR_HPP_
