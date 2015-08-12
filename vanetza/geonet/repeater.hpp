#ifndef REPEATER_HPP_AH49FXB1
#define REPEATER_HPP_AH49FXB1

#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <boost/heap/priority_queue.hpp>
#include <boost/optional.hpp>
#include <functional>
#include <memory>

namespace vanetza
{
namespace geonet
{

class Repeater
{
public:
    using Callback = std::function<void(const DataRequestVariant&, std::unique_ptr<DownPacket>)>;

    template<class REQUEST>
    void add(const REQUEST& request, const DownPacket& payload, Timestamp now)
    {
        if (request.repetition && has_further_repetition(*request.repetition)) {
            m_repetitions.emplace(request, payload,
                    now + Timestamp::duration_type(request.repetition->interval));
        }
    }

    void set_callback(const Callback&);
    void trigger(Timestamp now);

    /**
     * Get time stamp when next repetition should be triggered
     * \return time stamp of next repetition (if any)
     */
    boost::optional<Timestamp> next_trigger() const;

private:
    struct Repetition
    {
        Repetition(const DataRequestVariant&, const DownPacket&, Timestamp next);

        DataRequestVariant m_request;
        std::unique_ptr<DownPacket> m_payload;
        Timestamp m_next;
    };

    struct compare_repetition
    {
        bool operator()(const Repetition& lhs, const Repetition& rhs) const;
    };

    boost::heap::priority_queue<
            Repetition,
            boost::heap::compare<compare_repetition>
        > m_repetitions;
    Callback m_repeat_fn;
};

} // namespace geonet
} // namespace vanetza

#endif /* REPEATER_HPP_AH49FXB1 */

