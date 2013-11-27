#include "socket_descriptor.hpp"
#include <utility>

namespace vanetza
{

SocketDescriptor::SocketDescriptor(SocketDescriptor&& tmp) :
    mSockFd(scInvalidFd)
{
    using namespace std;
    swap(tmp.mSockFd, mSockFd);
}

SocketDescriptor& SocketDescriptor::operator=(SocketDescriptor&& tmp)
{
    using namespace std;
    swap(tmp.mSockFd, mSockFd);
    return *this;
}

} // namespace vanetza

