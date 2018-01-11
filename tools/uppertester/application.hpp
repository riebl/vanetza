#ifndef UPPERTESTER_APPLICATION_HPP
#define UPPERTESTER_APPLICATION_HPP

#include <vanetza/btp/data_interface.hpp>
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/router.hpp>

class Application : public vanetza::btp::IndicationInterface
{
public:
    using DataConfirm = vanetza::geonet::DataConfirm;
    using DataIndication = vanetza::btp::DataIndication;
    using DataRequest = vanetza::btp::DataRequestGeoNetParams;
    using DownPacketPtr = vanetza::geonet::Router::DownPacketPtr;
    using PortType = vanetza::btp::port_type;
    using UpPacketPtr = vanetza::geonet::Router::UpPacketPtr;

    Application() = default;
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;
    virtual ~Application() = default;

    virtual PortType port() = 0;

    DataConfirm request(const vanetza::btp::DataRequestA& request, DownPacketPtr packet);
    DataConfirm request(const vanetza::btp::DataRequestB& request, DownPacketPtr packet);

protected:
    vanetza::geonet::Router* router;
};

#endif /* UPPERTESTER_APPLICATION_HPP */
