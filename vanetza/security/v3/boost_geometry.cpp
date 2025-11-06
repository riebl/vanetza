#include <vanetza/asn1/security/PolygonalRegion.h>
#include <vanetza/asn1/security/TwoDLocation.h>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v3/boost_geometry.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

TwoDLocationModel make_model(const asn1::TwoDLocation& location)
{
    return TwoDLocationModel(location.longitude * 1e-7, location.latitude * 1e-7);
}

TwoDLocationModel make_model(const PositionFix& fix)
{
    return TwoDLocationModel(fix.longitude / units::degree, fix.latitude / units::degree);
}


TwoDLocationIterator::TwoDLocationIterator(const asn1::PolygonalRegion& region, std::size_t index) :
    m_region(&region), m_index(index)
{
}

void TwoDLocationIterator::increment()
{
    ++m_index;
}

void TwoDLocationIterator::decrement()
{
    --m_index;
}

void TwoDLocationIterator::advance(std::size_t n)
{
    m_index += n;
}

std::ptrdiff_t TwoDLocationIterator::distance_to(const TwoDLocationIterator& other) const
{
    return other.m_index - m_index;
}

bool TwoDLocationIterator::equal(const TwoDLocationIterator& other) const
{
    return m_region == other.m_region && m_index == other.m_index;
}

TwoDLocationModel TwoDLocationIterator::dereference() const
{
    assert(m_region != nullptr);
    assert(m_region->list.array != nullptr);
    assert(m_region->list.count > static_cast<decltype(m_region->list.count)>(m_index));
    return make_model(*m_region->list.array[m_index]);
}


PolygonalRegionRingAdapter::PolygonalRegionRingAdapter(const asn1::PolygonalRegion& region) :
    m_region(region)
{
    assert(m_region.list.array != nullptr);
}

PolygonalRegionRingAdapter::iterator PolygonalRegionRingAdapter::begin() const
{
    return TwoDLocationIterator(m_region, 0);
}

PolygonalRegionRingAdapter::iterator PolygonalRegionRingAdapter::end() const
{
    return TwoDLocationIterator(m_region, m_region.list.count);
}

std::size_t PolygonalRegionRingAdapter::size() const
{
    return m_region.list.count;
}

} // namespace v3
} // namespace security
} // namespace vanetza
