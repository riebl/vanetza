#include "io_vector.hpp"
#include "packet.hpp"

namespace vanetza
{

IoVector::IoVector(const Packet& packet)
{
    *this = packet;
}

IoVector& IoVector::operator=(const Packet& packet)
{
    mVector.clear();
    for (auto it = packet.begin(); it != packet.end(); ++it) {
        const ByteBuffer& buffer = it->second;
        iovec elem = { const_cast<uint8_t*>(&buffer[0]), buffer.size() };
        mVector.emplace_back(elem);
    }
    return *this;
}

void assignIoVec(msghdr& hdr, IoVector& io)
{
    hdr.msg_iov = io.base();
    hdr.msg_iovlen = io.length();
}

} // namespace vanetza
