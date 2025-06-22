#pragma once
#include <vanetza/security/v3/asn1_types.hpp>
#include <boost/geometry/core/closure.hpp>
#include <boost/geometry/core/cs.hpp> 
#include <boost/geometry/geometries/point.hpp>
#include <boost/iterator/iterator_facade.hpp>

namespace vanetza
{

// forward declaration
struct PositionFix;

namespace security
{
namespace v3
{

/**
 * TwoDLocationModel is a Boost.Geometry point model representing a 2D geographic location.
 */
using TwoDLocationModel = boost::geometry::model::point<double, 2, boost::geometry::cs::geographic<boost::geometry::degree>>;

/**
 * \brief Create a TwoDLocationModel from an ASN.1 TwoDLocation.
 *
 * \param location The ASN.1 TwoDLocation_t structure to convert.
 * \return A TwoDLocationModel representing the geographic location.
 */
TwoDLocationModel make_model(const asn1::TwoDLocation& location);
TwoDLocationModel make_model(const PositionFix&);

/**
 * TwoDLocationIterator allows traversal of ASN.1 PolygonalRegion providing TwoDLocationModel objects.
 */
class TwoDLocationIterator :
    public boost::iterator_facade<TwoDLocationIterator,
        TwoDLocationModel,
        boost::random_access_traversal_tag,
        TwoDLocationModel>
{
public:
    TwoDLocationIterator() = default;
    explicit TwoDLocationIterator(const asn1::PolygonalRegion& region, std::size_t index);

private:
    friend class boost::iterator_core_access;

    void increment();
    void decrement();
    void advance(std::size_t n);
    std::ptrdiff_t distance_to(const TwoDLocationIterator& other) const;
    bool equal(const TwoDLocationIterator& other) const;
    TwoDLocationModel dereference() const;

    const asn1::PolygonalRegion* m_region = nullptr;
    std::size_t m_index = 0;
};

/**
 * \brief Adapt ASN.1 PolygonalRegion to a Boost.Geometry ring.
 */
class PolygonalRegionRingAdapter
{
public:
    using iterator = TwoDLocationIterator;
    using const_iterator = TwoDLocationIterator;

    PolygonalRegionRingAdapter(const asn1::PolygonalRegion& region);
    iterator begin() const;
    iterator end() const;
    std::size_t size() const;

private:
    const asn1::PolygonalRegion& m_region;
};

} // namespace v3
} // namespace security
} // namespace vanetza

namespace boost
{
namespace geometry
{
namespace traits
{

template<> struct tag<vanetza::security::v3::PolygonalRegionRingAdapter> { using type = ring_tag; };
template<> struct closure<vanetza::security::v3::PolygonalRegionRingAdapter> { static const closure_selector value = open; };

} // namespace traits
} // namespace gemoetry
} // namespace boost
