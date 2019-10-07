#ifndef FLOW_CONTROL_HPP_PG7RKD8V
#define FLOW_CONTROL_HPP_PG7RKD8V

#include <vanetza/common/clock.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/dcc/transmission.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <boost/optional/optional.hpp>
#include <vanetza/access/access_category.hpp>
#include <list>
#include <memory>
#include <map>

namespace vanetza
{

// forward declarations
namespace access { class Interface; }
class Runtime;

namespace dcc
{

// forward declarations
class TransmitRateControl;

/**
 * FlowControl is a gatekeeper above access layer.
 *
 * There is a queue for each access category. Packets might be enqueued
 * because of exceeded transmission intervals determined by Scheduler.
 * If a packet's lifetime expires before transmission it will be dropped.
 */
class FlowControl : public RequestInterface
{
public:
    using PacketDropHook = Hook<access::AccessCategory, const ChunkPacket*>;
    using PacketTransmitHook = Hook<access::AccessCategory, const ChunkPacket*>;

    /**
     * Create FlowControl instance
     * \param rt Runtime used for timed actions, e.g. packet expiry
     * \param scheduler Scheduler providing transmission intervals
     * \param access Interface to access layer
     */
    FlowControl(Runtime&, TransmitRateControl&, access::Interface&);
    ~FlowControl();

    /**
     * Request packet transmission
     * \param request DCC request parameters
     * \param packet Packet data
     */
    void request(const DataRequest&, std::unique_ptr<ChunkPacket>) override;

    /**
     * Set callback to be invoked at packet drop. Replaces any previous callback.
     * \param cb Callback
     */
    void set_packet_drop_hook(PacketDropHook::callback_type&&);

    /**
     * Set callback to be invoked at packet transmission. Replaces any previous callback.
     * \param cb Callback
     */
    void set_packet_transmit_hook(PacketTransmitHook::callback_type&&);

    /**
     * Set length of each queue
     *
     * The first queue element is dropped when the length limit is hit.
     * \param length Maximum number of queue elements, 0 for unlimited length
     */
    void queue_length(std::size_t length);

    /**
     * Reschedule queued transmissions
     * This reevaluates TRC restrictions as well, packets may get transmitted earlier.
     */
    void reschedule();

private:
    struct PendingTransmission : public Transmission
    {
        PendingTransmission(Clock::time_point expiry, const DataRequest& request, std::unique_ptr<ChunkPacket> packet) :
            expiry(expiry), request(request), packet(std::move(packet)) {}

        Clock::time_point expiry;
        DataRequest request;
        std::unique_ptr<ChunkPacket> packet;

        Profile profile() const override { return request.dcc_profile; }
        const access::DataRateG5* data_rate() const override { return &access::G5_6Mbps; }
        std::size_t body_length() const override { return packet ? packet->size() : 0; }
    };

    using Queue = std::list<PendingTransmission>;

    void enqueue(const DataRequest&, std::unique_ptr<ChunkPacket>);
    boost::optional<PendingTransmission> dequeue();
    void transmit(const DataRequest&, std::unique_ptr<ChunkPacket>);
    bool transmit_immediately(const Transmission&) const;
    void drop_expired();
    bool empty() const;
    void trigger();
    void schedule_trigger(const Transmission&);
    PendingTransmission* next_transmission();
    Queue* next_queue();

    Runtime& m_runtime;
    TransmitRateControl& m_trc;
    access::Interface& m_access;
    std::map<access::AccessCategory, Queue, std::greater<access::AccessCategory>> m_queues;
    std::size_t m_queue_length;
    PacketDropHook m_packet_drop_hook;
    PacketTransmitHook m_packet_transmit_hook;
};

} // namespace dcc
} // namespace vanetza

#endif /* FLOW_CONTROL_HPP_PG7RKD8V */

