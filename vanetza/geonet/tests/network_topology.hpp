#include <vanetza/common/clock.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/geonet/data_indication.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <vanetza/geonet/tests/security_context.hpp>
#include <vanetza/net/mac_address.hpp>
#include <vanetza/units/length.hpp>
#include <boost/optional.hpp>
#include <functional>
#include <initializer_list>
#include <list>
#include <set>
#include <unordered_map>

namespace vanetza
{
namespace geonet
{

class NetworkTopology
{
public:
    enum class PacketDuplicationMode
    {
        Copy_Construct,
        Serialize
    };

    class RequestInterface : public dcc::RequestInterface
    {
    public:
        RequestInterface(NetworkTopology&, const MacAddress&);
        void request(const dcc::DataRequest&, std::unique_ptr<ChunkPacket>) override;
        void reset();
        void transmit();

        unsigned requests = 0;
        unsigned transmissions = 0;
        dcc::DataRequest last_request;
        std::unique_ptr<ChunkPacket> last_packet;

    private:
        NetworkTopology& network;
        const MacAddress& address;
    };

    class TransportHandler : public TransportInterface
    {
    public:
        void indicate(const DataIndication&, std::unique_ptr<UpPacket>) override;
        void reset();

        unsigned counter = 0;
        DataIndication last_indication;
        std::unique_ptr<UpPacket> last_packet;
    };

    class RouterContext
    {
    public:
        RouterContext(NetworkTopology&);
        void set_position_accuracy_indicator(bool flag);

        MacAddress mac_address;
        RequestInterface request_interface;
        TransportHandler transport_interface;
        ManualRuntime runtime;
        PositionFix position;
        SecurityContext security;
        Router router;
    };

    NetworkTopology();
    boost::optional<RouterContext&> get_host(const MacAddress&);
    boost::optional<Router&> get_router(const MacAddress&);
    boost::optional<RequestInterface&> get_interface(const MacAddress&);
    boost::optional<TransportHandler&> get_transport(const MacAddress&);
    const unsigned& get_counter_requests(const MacAddress&);
    const unsigned& get_counter_indications() const { return counter_indications; }
    ManagementInformationBase& get_mib() { return mib; }
    void add_router(const MacAddress&);
    void add_reachability(const MacAddress&, std::initializer_list<MacAddress>);
    void save_request(const dcc::DataRequest&, std::unique_ptr<ChunkPacket>);
    void dispatch();
    void send(Router&, const MacAddress&, const MacAddress&, const ChunkPacket&);
    void set_position(const MacAddress&, CartesianPosition);
    void advance_time(Clock::duration t);
    void reset_counters();
    void set_duplication_mode(PacketDuplicationMode);
    void set_network_delay(Clock::duration delay);
    void build_fully_meshed_reachability();

private:
    Clock::time_point next_event() const;
    using PendingTransmission = std::tuple<Clock::time_point, dcc::DataRequest, std::unique_ptr<ChunkPacket>>;

    std::unordered_map<MacAddress, unsigned> counter_requests;
    std::unordered_map<MacAddress, std::unique_ptr<RouterContext>> hosts;
    std::unordered_map<MacAddress, std::set<MacAddress>> reachability;
    std::list<PendingTransmission> requests;
    Clock::duration network_delay = Clock::duration::zero();
    Clock::time_point now;
    ManagementInformationBase mib;
    unsigned counter_indications;
    std::function<std::unique_ptr<UpPacket>(const ChunkPacket&)> fn_duplicate;
};

GeodeticPosition convert_cartesian_geodetic(const CartesianPosition&);
Area circle_dest_area(units::Length radius, units::Length midpoint_x, units::Length midpoint_y);

} // namespace geonet
} // namespace vanetza
