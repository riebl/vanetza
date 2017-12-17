#ifndef PENDING_PACKET_HPP_ZHSCP1UI
#define PENDING_PACKET_HPP_ZHSCP1UI

#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/lifetime.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/units/time.hpp>
#include <functional>
#include <memory>
#include <tuple>

namespace vanetza
{
namespace geonet
{

/**
 * PendingPacket combines PDU, payload and custom action code for pending processing steps.
 * This makes it easy to resume packet forwarding steps after buffering, for example.
 */
template<typename PDU, typename... Args>
class PendingPacket
{
public:
    using Packet = std::tuple<std::unique_ptr<PDU>, std::unique_ptr<DownPacket>>;
    using Function = std::function<void(Packet&&, Args&&...)>;

    PendingPacket() = default;

    PendingPacket(Packet&& packet, const Function& fn) :
        m_packet(std::move(packet)), m_function(fn) {}

    template<typename... OtherArgs>
    PendingPacket(PendingPacket<PDU, OtherArgs...>&& other, std::function<void(PendingPacket<PDU, OtherArgs...>&&, Args&&...)> fn) :
        m_packet(std::move(other).packet())
    {
        auto other_fn = other.action();
        m_function = [fn, other_fn](Packet&& packet, Args&&... args) {
            fn(PendingPacket<PDU, OtherArgs...> { std::move(packet), other_fn }, std::forward<Args>(args)...);
        };
    }

    template<typename... OtherArgs, typename... T>
    PendingPacket(PendingPacket<PDU, OtherArgs...>&& other, T&&... ts) :
        m_packet(std::move(other).packet())
    {
        typename PendingPacket<PDU, OtherArgs...>::Function other_action = other.action();
        std::function<void(Packet&&)> bound = std::bind(other_action, std::placeholders::_1, std::forward<T>(ts)...);
        m_function = [bound](Packet&& packet, Args&&... args) {
            bound(std::move(packet), std::forward<Args>(args)...);
        };
    }

    void process(Args&&... args)
    {
        if (std::get<0>(m_packet) && std::get<1>(m_packet)) {
            m_function(std::move(m_packet), std::forward<Args>(args)...);
        }
    }

    std::size_t length() const
    {
        const PDU* pdu = std::get<0>(m_packet).get();
        const DownPacket* payload = std::get<1>(m_packet).get();
        return (pdu ? get_length(*pdu) : 0) + (payload ? payload->size(OsiLayer::Transport, max_osi_layer()) : 0);
    }

    Clock::duration reduce_lifetime(Clock::duration queuing_time)
    {
        Clock::duration remaining = Clock::duration::zero();
        PDU* pdu_ptr = std::get<0>(m_packet).get();
        if (pdu_ptr) {
            using vanetza::units::clock_cast;
            Clock::duration packet_lifetime = clock_cast(pdu_ptr->basic().lifetime.decode());
            if (queuing_time <= Clock::duration::zero()) {
                remaining = packet_lifetime;
            } else if (queuing_time < packet_lifetime) {
                remaining = packet_lifetime - queuing_time;
                pdu_ptr->basic().lifetime.encode(clock_cast(remaining));
            } else {
                pdu_ptr->basic().lifetime = Lifetime::zero();
            }
        }
        return remaining;
    }

    const PDU& pdu() const
    {
        const PDU* ptr = std::get<0>(m_packet).get();
        assert(ptr);
        return *ptr;
    }

    const DownPacket& payload() const
    {
        const DownPacket* ptr = std::get<1>(m_packet).get();
        assert(ptr);
        return *ptr;
    }

    Function action() const { return m_function; }

    Packet packet() && { return std::move(m_packet); }

    PendingPacket duplicate()
    {
        const PDU* pdu_ptr = std::get<0>(m_packet).get();
        std::unique_ptr<PDU> pdu_dup { pdu_ptr ? new PDU(*pdu_ptr) : nullptr };
        std::unique_ptr<DownPacket> payload_dup;
        if (!pdu_ptr || pdu_ptr->secured()) {
            payload_dup.reset(new DownPacket());
        } else if (const DownPacket* payload_ptr = std::get<1>(m_packet).get()) {
            payload_dup = vanetza::duplicate(*payload_ptr);
        }
        return PendingPacket(std::make_tuple(std::move(pdu_dup), std::move(payload_dup)), m_function);
    }

private:
    Packet m_packet;
    Function m_function;
};

} // namespace geonet
} // namespace vanetza

#endif /* PENDING_PACKET_HPP_ZHSCP1UI */

