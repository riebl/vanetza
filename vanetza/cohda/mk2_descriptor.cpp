#include "mk2_descriptor.hpp"
#include <algorithm>
#include <cassert>

ByteBuffer createMk2TxDescriptor(const tMK2TxDescriptor& tx)
{
	ByteBuffer buffer(sizeof(tMK2TxDescriptor));
	assert(buffer.size() == sizeof(tMK2TxDescriptor));
	const uint8_t* tx_bytes = reinterpret_cast<const uint8_t*>(&tx);
	std::copy(&tx_bytes[0], &tx_bytes[sizeof(tMK2TxDescriptor)], &buffer[0]);
	return buffer;
}
