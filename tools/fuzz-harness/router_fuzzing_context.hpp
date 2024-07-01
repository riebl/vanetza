#ifndef VANETZA_ROUTER_FUZZING_CONTEXT_HPP
#define VANETZA_ROUTER_FUZZING_CONTEXT_HPP

#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <vanetza/geonet/tests/security_context.hpp>

namespace vanetza
{

class RouterFuzzingContext {
public:
    RouterFuzzingContext();
    void initialize();
    void indicate(ByteBuffer&& buffer);

private:
    ManualRuntime runtime;
    geonet::ManagementInformationBase mib;
    std::unique_ptr<geonet::Router> router;
    std::unique_ptr<dcc::RequestInterface> req_ifc;
    std::unique_ptr<geonet::TransportInterface> ind_ifc;
    SecurityContext security;
};

} // namespace vanetza

#endif //VANETZA_ROUTER_FUZZING_CONTEXT_HPP
