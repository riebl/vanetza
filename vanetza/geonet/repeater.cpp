#include "repeater.hpp"
#include "router.hpp"
#include "data_confirm.hpp"
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace geonet
{

struct repetition_dispatcher : public boost::static_visitor<void>
{
    repetition_dispatcher(Router& router, std::unique_ptr<DownPacket> payload)
        : m_router(router), m_payload(std::move(payload))
    {}

    template<class REQUEST>
    void operator()(const REQUEST& request)
    {
        m_router.request(request, std::move(m_payload));
    }

    Router& m_router;
    std::unique_ptr<DownPacket> m_payload;
};

Repeater::Repetition::Repetition(const DataRequestVariant& request,
        const DownPacket& payload, Timestamp next) :
    m_request(request), m_payload(new DownPacket(payload)), m_next(next)
{
}

void Repeater::trigger(Router& router, Timestamp now)
{
    while (!m_repetitions.empty() && m_repetitions.top().m_next <= now) {
        const Repetition& repetition = m_repetitions.top();
        auto payload = const_cast<std::unique_ptr<DownPacket>&&>(repetition.m_payload);
        repetition_dispatcher dispatcher(router, std::move(payload));
        boost::apply_visitor(dispatcher, repetition.m_request);
        m_repetitions.pop();
    }
}

boost::optional<Timestamp> Repeater::next_trigger() const
{
    boost::optional<Timestamp> next;
    if (!m_repetitions.empty()) {
        next = m_repetitions.top().m_next;
    }
    return next;
}

bool Repeater::compare_repetition::operator()(
        const Repetition& lhs,
        const Repetition& rhs
    ) const
{
    return lhs.m_next > rhs.m_next;
}

} // namespace geonet
} // namespace vanetza

