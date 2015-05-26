#include "repeater.hpp"
#include "data_request.hpp"

namespace vanetza
{
namespace geonet
{

Repeater::Repetition::Repetition(const DataRequestVariant& request,
        const DownPacket& payload, Timestamp next) :
    m_request(request), m_payload(new DownPacket(payload)), m_next(next)
{
}

void Repeater::trigger(Timestamp now)
{
    while (!m_repetitions.empty() && m_repetitions.top().m_next <= now) {
        const Repetition& repetition = m_repetitions.top();
        auto payload = const_cast<std::unique_ptr<DownPacket>&&>(repetition.m_payload);
        if (m_repeat_fn) {
            m_repeat_fn(repetition.m_request, std::move(payload));
        }
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

void Repeater::set_callback(const Callback& cb)
{
    m_repeat_fn = cb;
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

