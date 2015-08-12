#include "repeater.hpp"
#include "data_request.hpp"
#include <cassert>

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
        // This cast is safe because element is removed afterwards anyway
        Repetition& repetition = const_cast<Repetition&>(m_repetitions.top());
        if (m_repeat_fn) {
            DataRequest& request = access_request(repetition.m_request);
            assert(request.repetition);

            // reduce remaining interval by one step and occurred triggering delay
            decrement_by_one(*request.repetition);
            Timestamp::duration_type delayed = now - repetition.m_next;
            request.repetition->maximum -= units::Duration(delayed);

            // reset repetition data if this is the last repetition
            if (!has_further_repetition(request)) {
                request.repetition.reset();
            }
            m_repeat_fn(repetition.m_request, std::move(repetition.m_payload));
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

