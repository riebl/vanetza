#ifndef INTERFACE_HPP_4SUUTA6X
#define INTERFACE_HPP_4SUUTA6X

#include <memory>

namespace vanetza
{

// forward declarations
class ChunkPacket;

namespace dcc
{

// forward declarations
struct DataRequest;

/**
 * DCC_access interface for data request from upper layers
 */
class RequestInterface
{
public:
    virtual void request(const DataRequest&, std::unique_ptr<ChunkPacket>) = 0;
    virtual ~RequestInterface() = default;
};

/**
 * Null implemenation of DCC data request interface
 */
class NullRequestInterface : public RequestInterface
{
public:
    void request(const DataRequest&, std::unique_ptr<ChunkPacket>) override {}
};

} // namespace dcc
} // namespace vanetza

#endif /* INTERFACE_HPP_4SUUTA6X */

