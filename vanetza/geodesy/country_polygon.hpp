#pragma once
#include <boost/geometry/core/cs.hpp>
#include <boost/geometry/geometries/multi_polygon.hpp>
#include <boost/geometry/geometries/point.hpp>
#include <boost/geometry/geometries/polygon.hpp>

namespace vanetza
{
namespace geodesy
{
namespace country
{
using CoordinateSystem = boost::geometry::cs::geographic<boost::geometry::degree>;
using Point = boost::geometry::model::point<double, 2, CoordinateSystem>;
using Ring = boost::geometry::model::ring<Point>;
using Polygon = boost::geometry::model::polygon<Point>;
using MultiPolygon = boost::geometry::model::multi_polygon<Polygon>;
} // namespace country

using CountryPolygon = country::MultiPolygon;

} // namespace geodesy
} // namespace vanetza
