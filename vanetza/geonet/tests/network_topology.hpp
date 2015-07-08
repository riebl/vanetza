#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/data_indication.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/net/mac_address.hpp>
#include <boost/optional.hpp>
#include <GeographicLib/Geocentric.hpp>
#include <GeographicLib/Geodesic.hpp>
#include <GeographicLib/LocalCartesian.hpp>
#include <list>
#include <unordered_map>

using namespace vanetza;
using namespace vanetza::geonet;
using namespace vanetza::dcc;
using namespace vanetza::units::si;

class NetworkTopology
{
public:
    class RequestInterface : public dcc::RequestInterface
    {
    public:
        RequestInterface(NetworkTopology&, const MacAddress&);
        void request(const dcc::DataRequest&, std::unique_ptr<ChunkPacket>) override;

        dcc::DataRequest last_request;
        std::unique_ptr<ChunkPacket> last_packet;

    private:
        NetworkTopology& network;
        const MacAddress& address;
    };

    class RouterContext
    {
    public:
        RouterContext(NetworkTopology&);

        MacAddress mac_address;
        RequestInterface request_interface;
        Router router;
    };

    boost::optional<RouterContext&> get_host(const MacAddress&);
    boost::optional<Router&> get_router(const MacAddress&);
    boost::optional<RequestInterface&> get_interface(const MacAddress&);
    const unsigned& get_counter_requests(const MacAddress&);
    const unsigned& get_counter_indications() const { return counter_indications; }
    const ManagementInformationBase& get_mib() const { return mib; }
    void add_router(const MacAddress&);
    void add_reachability(const MacAddress&, std::list<MacAddress>);
    void save_request(const dcc::DataRequest&, std::unique_ptr<ChunkPacket>);
    void dispatch();
    void send(const MacAddress&, const MacAddress&);
    void set_position(const MacAddress&, CartesianPosition);
    void advance_time(Timestamp::duration_type);
    void reset_counters();

private:
    std::unordered_map<MacAddress, unsigned> counter_requests;
    std::unordered_map<MacAddress, std::unique_ptr<RouterContext>> hosts;
    std::unordered_map<MacAddress, std::list<MacAddress> > reachability;
    std::list<std::tuple<dcc::DataRequest, std::unique_ptr<ChunkPacket>>> requests;
    Timestamp now;
    ManagementInformationBase mib;
    unsigned counter_indications;
};

GeodeticPosition convert_cartesian_geodetic(const CartesianPosition&);
Area circle_dest_area(double radius, double midpoint_x, double midpoint_y);
