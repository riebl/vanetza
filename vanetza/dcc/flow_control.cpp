#include "data_request.hpp"
#include "flow_control.hpp"
#include "mapping.hpp"
#include "scheduler.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/access/interface.hpp>
#include <vanetza/common/runtime.hpp>
#include <algorithm>

namespace vanetza
{
namespace dcc
{

FlowControl::FlowControl(Runtime& runtime, Scheduler& scheduler, access::Interface& ifc) :
    m_runtime(runtime), m_scheduler(scheduler), m_access(ifc)
{
}

void FlowControl::request(const DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    if (transmit_immediately(request)) {
        transmit(request, std::move(packet));
    } else {
        enqueue(request, std::move(packet));
    }
}

void FlowControl::trigger()
{
    auto transmission = dequeue();
    if (transmission) {
        transmit(std::get<1>(*transmission), std::move(std::get<2>(*transmission)));
    }

    Transmission* next = next_transmission();
    if (next) {
        const DataRequest& request = std::get<1>(*next);
        schedule_trigger(request.dcc_profile);
    }
}

void FlowControl::schedule_trigger(Profile dcc_profile)
{
    auto callback_delay = m_scheduler.delay(dcc_profile);
    m_runtime.schedule(callback_delay, std::bind(&FlowControl::trigger, this));
}

void FlowControl::enqueue(const DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    const bool first_packet = empty();
    const auto ac = map_profile_onto_ac(request.dcc_profile);
    auto expiry = m_runtime.now() + request.lifetime;
    m_queues[ac].emplace_back(expiry, request, std::move(packet));

    if (first_packet) {
        schedule_trigger(request.dcc_profile);
    }
}

boost::optional<FlowControl::Transmission> FlowControl::dequeue()
{
    drop_expired();

    boost::optional<Transmission> transmission;
    Queue* queue = next_queue();
    if (queue) {
        transmission = std::move(queue->front());
        queue->pop_front();
    }

    return transmission;
}

bool FlowControl::transmit_immediately(const DataRequest& request) const
{
    const auto ac = map_profile_onto_ac(request.dcc_profile);

    // is there any packet enqueued with equal or higher priority?
    bool contention = false;
    for (auto it = m_queues.cbegin(); it != m_queues.end(); ++it) {
        if (it->first >= ac && !it->second.empty()) {
            contention = true;
            break;
        }
    }

    return !contention && m_scheduler.delay(request.dcc_profile) == Clock::duration::zero();
}

bool FlowControl::empty() const
{
    return std::all_of(m_queues.cbegin(), m_queues.cend(),
            [](const std::pair<AccessCategory, const Queue&>& kv) {
                return kv.second.empty();
            });
}

FlowControl::Queue* FlowControl::next_queue()
{
    Queue* queue = nullptr;
    for (auto& kv : m_queues) {
        if (!kv.second.empty()) {
            queue = &kv.second;
            break;
        }
    }
    return queue;
}

FlowControl::Transmission* FlowControl::next_transmission()
{
    Queue* queue = next_queue();
    return queue ? &queue->front() : nullptr;
}

void FlowControl::drop_expired()
{
    for (auto& kv : m_queues) {
        AccessCategory ac = kv.first;
        Queue& queue = kv.second;
        queue.remove_if([this, ac](const Transmission& transmission) {
            const Clock::time_point expiry = std::get<0>(transmission);
            bool drop = expiry < m_runtime.now();
            if (drop) {
                m_packet_drop_hook(ac);
            }
            return drop;
        });
    }
}

void FlowControl::transmit(const DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    access::DataRequest mac_req;
    mac_req.source_addr = request.source;
    mac_req.destination_addr = request.destination;
    mac_req.ether_type = request.ether_type;
    mac_req.access_category = map_profile_onto_ac(request.dcc_profile);

    m_scheduler.notify(request.dcc_profile);
    m_access.request(mac_req, std::move(packet));
}

void FlowControl::set_packet_drop_hook(PacketDropHook::callback_type&& cb)
{
    m_packet_drop_hook = std::move(cb);
}

} // namespace dcc
} // namespace vanetza
