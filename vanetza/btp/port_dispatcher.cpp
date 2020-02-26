#include "port_dispatcher.hpp"
#include "data_indication.hpp"
#include <vanetza/geonet/data_indication.hpp>
#include <algorithm>
#include <cassert>

namespace vanetza
{
namespace btp
{

boost::optional<DataIndication> parse_btp_header(const geonet::DataIndication& gn_ind, PacketVariant& packet)
{
    boost::optional<DataIndication> indication;

    switch (gn_ind.upper_protocol) {
        case geonet::UpperProtocol::BTP_A: {
            HeaderA hdr = parse_btp_a(packet);
            indication = DataIndication(gn_ind, hdr);
            }
            break;
        case geonet::UpperProtocol::BTP_B: {
            HeaderB hdr = parse_btp_b(packet);
            indication = DataIndication(gn_ind, hdr);
            }
            break;
        default:
            // drop non-BTP packet
            break;
    }

    return indication;
}

void PortDispatcher::add_promiscuous_hook(PromiscuousHook* hook)
{
    if (hook != nullptr) {
        auto it = std::find(m_promiscuous_hooks.begin(), m_promiscuous_hooks.end(), hook);
        if (it == m_promiscuous_hooks.end()) {
            m_promiscuous_hooks.push_back(hook);
        }
    }
}

void PortDispatcher::remove_promiscuous_hook(PromiscuousHook* hook)
{
    m_promiscuous_hooks.remove(hook);
}

void PortDispatcher::set_interactive_handler(
        port_type port,
        IndicationInterface* handler)
{
    m_interactive_handlers[port] = handler;
}

void PortDispatcher::set_non_interactive_handler(
        port_type port,
        IndicationInterface* handler)
{
    m_non_interactive_handlers[port] = handler;
}

void PortDispatcher::indicate(
        const geonet::DataIndication& gn_ind,
        std::unique_ptr<UpPacket> packet)
{
    assert(packet);
    boost::optional<DataIndication> btp_ind = parse_btp_header(gn_ind, *packet);
    IndicationInterface* handler = nullptr;

    if (btp_ind) {
        if (btp_ind->source_port) {
            handler = m_interactive_handlers[btp_ind->destination_port];
        } else {
            handler = m_non_interactive_handlers[btp_ind->destination_port];
        }

        for (PromiscuousHook* hook : m_promiscuous_hooks) {
            hook->tap_packet(*btp_ind, *packet);
        }

        if (handler) {
            handler->indicate(*btp_ind, std::move(packet));
        } else {
            hook_undispatched(gn_ind, &btp_ind.get());
        }
    } else {
        hook_undispatched(gn_ind, nullptr);
    }
}

} // namespace btp
} // namespace vanetza
