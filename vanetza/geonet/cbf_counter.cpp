#include <vanetza/geonet/cbf_counter.hpp>
#include <cassert>

namespace vanetza
{
namespace geonet
{

void CbfCounterImmortal::add(const id_type& id)
{
    ++m_counters[id];
}

void CbfCounterImmortal::increment(const id_type& id)
{
    ++m_counters[id];
}

auto CbfCounterImmortal::counter(const id_type& id) const -> counter_type
{
    counter_type count = 0;
    auto found = m_counters.find(id);
    if (found != m_counters.end()) {
        count = found->second;
    }
    return count;
}

void CbfCounterContending::add(const id_type& id)
{
    m_counters[id] = 1;
}

void CbfCounterContending::remove(const id_type& id)
{
    m_counters.erase(id);
}

CbfCounterFading::CbfCounterFading(Runtime& rt, Clock::duration lifetime) :
    m_counters(rt)
{
    m_counters.set_lifetime(lifetime);
}

void CbfCounterFading::add(const id_type& id)
{
    ++m_counters.refresh(id);
    m_counters.drop_expired();
}

void CbfCounterFading::increment(const id_type& id)
{
    ++m_counters.get_value(id);
}

auto CbfCounterFading::counter(const id_type& id) const -> counter_type
{
    auto* count = m_counters.get_value_ptr(id);
    return count ? *count : 0;
}

} // namespace geonet
} // namespace vanetza
