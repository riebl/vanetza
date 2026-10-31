#include <vanetza/facilities/path_history.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/units/cmath.hpp>
#include <algorithm>
#include <cassert>

namespace vanetza {
namespace facilities {

const units::Length cTraceAllowableError = 0.47 * units::si::meter;
const units::Length cTraceMaxDeltaDistance = 22.5 * units::si::meter;
const units::Angle cTraceDeltaPhi = units::Angle(1.0 * units::degree);

namespace {

// magnitude of shortest rotation, i.e. left and right turns alike and across north
units::Angle heading_change(units::Angle a, units::Angle b)
{
    using boost::math::double_constants::pi;

    static const units::Angle full_circle = 2.0 * pi * units::si::radian;
    const units::Angle abs_diff = fmod(abs(a - b), full_circle);
    return std::min(abs_diff, full_circle - abs_diff);
}

} // namespace

PathHistory::PathHistory() : PathHistory(Parameters{})
{
}

PathHistory::PathHistory(const Parameters& params) :
    m_params(params), m_samples(3)
{
}

const PathPoint& PathHistory::starting() const
{
    assert(!m_concise.empty());
    return m_concise.front();
}

const PathPoint& PathHistory::previous() const
{
    assert(m_samples.size() > 1);
    return m_samples[1];
}

const PathPoint& PathHistory::next() const
{
    assert(!m_samples.empty());
    return m_samples.front();
}

void PathHistory::addSample(const PathPoint& point)
{
    m_samples.push_front(point);
    if (m_concise.empty()) {
        m_concise.push_front(m_samples.front());
    }

    updateConcisePoints();
    truncateConcisePoints();
}

void PathHistory::clear()
{
    m_samples.clear();
    m_concise.clear();
}

const PathPoint& PathHistory::getReferencePoint() const
{
    static const PathPoint scDefaultPathPoint = PathPoint();

    if (m_samples.empty()) {
        return scDefaultPathPoint;
    } else {
        return m_samples.front();
    }
}

void PathHistory::updateConcisePoints()
{
    if (m_samples.full()) {
        const auto actual_chord_length = chord_length(starting(), next());
        units::Length actual_error;
        if (actual_chord_length > m_params.chord_length_threshold) {
            actual_error = m_params.allowable_error + 1.0 * units::si::meter;
        } else {
            const units::Angle delta_phi = heading_change(starting().heading, next().heading);
            if (delta_phi < m_params.small_delta_phi) {
                actual_error = 0.0 * units::si::meter;
            } else {
                const units::Length estimated_radius = actual_chord_length / (2 * sin(delta_phi * 0.5));
                const units::Length d = estimated_radius * cos(0.5 * delta_phi);
                actual_error = estimated_radius - d;
            }
        }

        if (actual_error > m_params.allowable_error) {
            m_concise.push_front(previous());
        }
    }
}

void PathHistory::truncateConcisePoints()
{
    units::Length distance = 0.0 * units::si::meter;
    if (m_concise.size() > 2) {
        auto previous = m_concise.begin();
        auto current = ++m_concise.begin();
        for (; current != m_concise.end(); ++previous, ++current) {
            distance += chord_length(*previous, *current);
            if (distance >= m_params.retention_distance) {
                m_concise.erase(++current, m_concise.end());
                break;
            }
        }
    }
}

boost::iterator_range<std::list<PathPoint>::const_iterator>
PathHistory::getConcisePointsMinLength(units::Length distance) const
{
    return getConcisePointsMinLength(distance, m_concise.size());
}

boost::iterator_range<std::list<PathPoint>::const_iterator>
PathHistory::getConcisePointsMinLength(units::Length distance, std::size_t max_points) const
{
    units::Length covered = 0.0 * units::si::meter;
    std::size_t count = 0;
    const PathPoint* previous = nullptr;
    auto cut = m_concise.begin();
    for (; cut != m_concise.end() && count < max_points; ++cut, ++count) {
        if (previous != nullptr) {
            covered += chord_length(*previous, *cut);
        }
        previous = &*cut;
        if (covered >= distance) {
            ++cut; // include the point reaching the distance
            break;
        }
    }
    return { m_concise.begin(), cut };
}

boost::iterator_range<std::list<PathPoint>::const_iterator>
PathHistory::getConcisePointsMaxLength(units::Length distance) const
{
    return getConcisePointsMaxLength(distance, m_concise.size());
}

boost::iterator_range<std::list<PathPoint>::const_iterator>
PathHistory::getConcisePointsMaxLength(units::Length distance, std::size_t max_points) const
{
    units::Length covered = 0.0 * units::si::meter;
    std::size_t count = 0;
    const PathPoint* previous = nullptr;
    auto cut = m_concise.begin();
    for (; cut != m_concise.end() && count < max_points; ++cut, ++count) {
        if (previous != nullptr) {
            covered += chord_length(*previous, *cut);
            if (covered > distance) {
                break; // exclude the point beyond the distance
            }
        }
        previous = &*cut;
    }
    return { m_concise.begin(), cut };
}

} // namespace facilities
} // namespace vanetza
