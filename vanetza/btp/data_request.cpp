#include <vanetza/btp/data_request.hpp>

namespace vanetza
{
namespace btp
{

DataRequestA::DataRequestA() :
    destination_port(0),
    source_port(0)
{
}

DataRequestB::DataRequestB() :
    destination_port(0),
    destination_port_info(0)
{
}

} // namespace btp
} // namespace vanetza
