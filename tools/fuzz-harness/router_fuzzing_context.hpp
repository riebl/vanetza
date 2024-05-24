#ifndef VANETZA_ROUTER_FUZZING_CONTEXT_HPP
#define VANETZA_ROUTER_FUZZING_CONTEXT_HPP

#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/tests/fake_interfaces.hpp>
#include <vanetza/geonet/tests/security_context.hpp>

class RouterFuzzingContext {
public:
    RouterFuzzingContext() :
        runtime(vanetza::Clock::at("2010-12-23 18:29")), security(runtime)
    {
        initialize();
    }

    void initialize()
    {
        router = std::make_unique<geonet::Router>(runtime, mib);
        geonet::Address gn_addr;
        gn_addr.mid(MacAddress{0, 0, 0, 0, 0, 1});
        router->set_address(gn_addr);
        router->set_access_interface(&req_ifc);
        router->set_security_entity(&security.entity());
        router->set_transport_handler(geonet::UpperProtocol::BTP_B, &ind_ifc);
    }

    void indicate(ByteBuffer&& buffer)
    {
        MacAddress source { 0, 0, 0, 0, 0, 2 };
        MacAddress destination { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        auto packet = std::make_unique<geonet::UpPacket>(CohesivePacket { std::move(buffer), OsiLayer::Network });
        router->indicate(std::move(packet), source, destination);
    }

    ManualRuntime runtime;
    geonet::ManagementInformationBase mib;
    std::unique_ptr<geonet::Router> router;
    SecurityContext security;
    FakeRequestInterface req_ifc;
    FakeTransportInterface ind_ifc;
};

#endif //VANETZA_ROUTER_FUZZING_CONTEXT_HPP
