#ifndef PORT_DISPATCHER_HPP_YZ0UTAUF
#define PORT_DISPATCHER_HPP_YZ0UTAUF

#include <vanetza/btp/data_interface.hpp>
#include <vanetza/btp/header.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <vanetza/net/packet.hpp>
#include <list>
#include <unordered_map>

namespace vanetza
{

namespace btp
{

class PortDispatcher : public geonet::TransportInterface
{
public:
    class PromiscuousHook
    {
    public:
        /**
         * Called when a BTP packet is received, regardless of its destination port
         * \param indication BTP data indication
         * \param packet Read-only view of packet
         */
        virtual void tap_packet(const DataIndication&, const UpPacket&) = 0;
        virtual ~PromiscuousHook() {}
    };

    /**
     * Register a handler for incoming BTP-A (interactive) packets
     * \param port BTP-A destination port
     * \param interface Handler for given destination port
     * \note Use a nullptr as handler to disable dispatching of destination port
     * \note Only one handler can be registered per port
     */
    void set_interactive_handler(port_type, IndicationInterface*);

    /**
     * Register a handler for incoming BTP-B (non-interactive) packets
     * \param port BTP-B destination port
     * \param interface Handler for given destination port
     * \note Use a nullptr as handler to disable dispatching of destination port
     * \note Only one handler can be registered per port
     */
    void set_non_interactive_handler(port_type, IndicationInterface*);

    /**
     * Get handler registered for a BTP-A (interactive) port
     * \param port BTP-A destination port
     * \return registered handler or nullptr if none
     */
    IndicationInterface* get_interactive_handler(port_type) const;

    /**
     * Get handler registered for a BTP-B (non-interactive) port
     * \param port BTP-B destination port
     * \return registered handler or nullptr if none
     */
    IndicationInterface* get_non_interactive_handler(port_type) const;

    /**
     * Add a hook listening for all incoming BTP packets
     * \param hook A hook implementing the promiscuous hook interface
     * \note Each registered hook is invoked only once per indication
     */
    void add_promiscuous_hook(PromiscuousHook* hook);

    /**
     * Remove promiscuous hook
     * \param hook pointer to previously added hook
     */
    void remove_promiscuous_hook(PromiscuousHook*);

    // Implementation of geonet::TransportInterface
    void indicate(const geonet::DataIndication&, std::unique_ptr<UpPacket>) override;

    /**
     * Hook invoked for all indicated but undispatched packets
     * \note BTP data indication can be nullptr
     */
    Hook<const geonet::DataIndication&, const btp::DataIndication*> hook_undispatched;

private:
    typedef std::unordered_map<port_type, IndicationInterface*> port_map;
    typedef std::list<PromiscuousHook*> hook_list;

    static IndicationInterface* find_handler(const port_map&, port_type);
    static void set_handler(port_map&, port_type, IndicationInterface*);

    port_map m_interactive_handlers;
    port_map m_non_interactive_handlers;
    hook_list m_promiscuous_hooks;
};

} // namespace btp
} // namespace vanetza

#endif /* PORT_DISPATCHER_HPP_YZ0UTAUF */

