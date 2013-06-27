#ifndef BYTE_BUFFER_HPP_7NOEQO4F
#define BYTE_BUFFER_HPP_7NOEQO4F

#include <cstdint>
#include <vector>

typedef std::vector<uint8_t> ByteBuffer;

// TODO: Propagate MASK constness to buffer type
template<typename MASK>
MASK* applyMask(ByteBuffer& buffer)
{
    MASK* mask = nullptr;
    if (sizeof(MASK) <= buffer.size()) {
        mask = reinterpret_cast<MASK*>(&buffer[0]);
    }
    return mask;
}

#endif /* BYTE_BUFFER_HPP_7NOEQO4F */
