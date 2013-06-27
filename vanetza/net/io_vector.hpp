#ifndef IO_VECTOR_HPP_A3ANMI8B
#define IO_VECTOR_HPP_A3ANMI8B

#include <vector>
#include <sys/socket.h>
#include <sys/types.h>

class Packet;

class IoVector
{
public:
    IoVector(const Packet& packet);
    IoVector& operator=(const Packet&);
    std::size_t length() const { return mVector.size(); }
    iovec* base() { return &mVector[0]; }

private:
    std::vector<iovec> mVector;
};

void assignIoVec(msghdr&, IoVector&);

#endif /* IO_VECTOR_HPP_A3ANMI8B */
