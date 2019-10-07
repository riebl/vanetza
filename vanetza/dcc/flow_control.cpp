#include "data_request.hpp"
#include "flow_control.hpp"
#include "mapping.hpp"
#include "transmit_rate_control.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/access/interface.hpp>
#include <vanetza/common/runtime.hpp>
#include <algorithm>

namespace vanetza
{
namespace dcc
{

FlowControl::FlowControl(Runtime& runtime, TransmitRateControl& trc, access::Interface& ifc) :
    m_runtime(runtime), m_trc(trc), m_access(ifc), m_queue_length(0)
{
}

FlowControl::~FlowControl()
{
    m_runtime.cancel(this);
}

void FlowControl::request(const DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    drop_expired();

    const TransmissionLite transmission { request.dcc_profile, packet->size() };
    if (transmit_immediately(transmission)) {
        m_trc.notify(transmission);
        transmit(request, std::move(packet));
    } else {
        enqueue(request, std::move(packet));
    }
}

void FlowControl::trigger()
{
    drop_expired();
    auto transmission = dequeue();
    if (transmission) {
        m_trc.notify(*transmission);
        transmit(transmission->request, std::move(transmission->packet));
    }

    PendingTransmission* next = next_transmission();
    if (next) {
        schedule_trigger(*next);
    }
}

void FlowControl::schedule_trigger(const Transmission& tx)
{
    auto callback_delay = m_trc.delay(tx);
    m_runtime.schedule(callback_delay, std::bind(&FlowControl::trigger, this), this);
}

void FlowControl::enqueue(const DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    const bool first_packet = empty();
    const auto ac = map_profile_onto_ac(request.dcc_profile);
    auto expiry = m_runtime.now() + request.lifetime;
    while (m_queue_length > 0 && m_queues[ac].size() >= m_queue_length) {
        m_queues[ac].pop_front();
        m_packet_drop_hook(ac, packet.get());
    }
    m_queues[ac].emplace_back(expiry, request, std::move(packet));

    if (first_packet) {
        schedule_trigger(m_queues[ac].back());
    }
}

boost::optional<FlowControl::PendingTransmission> FlowControl::dequeue()
{
    boost::optional<PendingTransmission> transmission;
    Queue* queue = next_queue();
    if (queue) {
        transmission = std::move(queue->front());
        queue->pop_front();
    }

    return transmission;
}

bool FlowControl::transmit_immediately(const Transmission& transmission) const
{
    const auto ac = map_profile_onto_ac(transmission.profile());

    // is there any packet enqueued with equal or higher priority?
    bool contention = false;
    for (auto it = m_queues.cbegin(); it != m_queues.end(); ++it) {
        if (it->first >= ac && !it->second.empty()) {
            contention = true;
            break;
        }
    }

    return !contention && m_trc.delay(transmission) == Clock::duration::zero();
}

bool FlowControl::empty() const
{
    return std::all_of(m_queues.cbegin(), m_queues.cend(),
            [](const std::pair<access::AccessCategory, const Queue&>& kv) {
                return kv.second.empty();
            });
}

FlowControl::Queue* FlowControl::next_queue()
{
    Queue* next = nullptr;
    Clock::duration min_delay = Clock::duration::max();

    for (auto& kv : m_queues) {
        Queue& queue = kv.second;
        if (!queue.empty()) {
            const auto delay = m_trc.delay(queue.front());
            if (delay < min_delay) {
                min_delay = delay;
                next = &queue;
            }
        }
    }
    return next;
}

FlowControl::PendingTransmission* FlowControl::next_transmission()
{
    Queue* queue = next_queue();
    return queue ? &queue->front() : nullptr;
}

void FlowControl::drop_expired()
{
    for (auto& kv : m_queues) {
        access::AccessCategory ac = kv.first;
        Queue& queue = kv.second;
        queue.remove_if([this, ac](const PendingTransmission& transmission) {
            bool drop = transmission.expiry < m_runtime.now();
            if (drop) {
                m_packet_drop_hook(ac, transmission.packet.get());
            }
            return drop;
        });
    }
}

void FlowControl::transmit(const DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    access::DataRequest access_request;
    access_request.source_addr = request.source;
    access_request.destination_addr = request.destination;
    access_request.ether_type = request.ether_type;
    access_request.access_category = map_profile_onto_ac(request.dcc_profile);

    m_packet_transmit_hook(access_request.access_category, packet.get());
    m_access.request(access_request, std::move(packet));
}

void FlowControl::set_packet_drop_hook(PacketDropHook::callback_type&& cb)
{
    m_packet_drop_hook = std::move(cb);
}

void FlowControl::set_packet_transmit_hook(PacketTransmitHook::callback_type&& cb)
{
    m_packet_transmit_hook = std::move(cb);
}

void FlowControl::queue_length(std::size_t length)
{
    m_queue_length = length;
}

void FlowControl::reschedule()
{
    PendingTransmission* next = next_transmission();
    if (next) {
        m_runtime.cancel(this);
        schedule_trigger(*next);
    }
}

} // namespace dcc
} // namespace vanetza
