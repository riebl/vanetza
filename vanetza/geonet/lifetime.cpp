#include "lifetime.hpp"
#include "serialization.hpp"
#include <vanetza/common/byte_order.hpp>
#include <boost/units/cmath.hpp>
#include <stdexcept>

namespace vanetza
{
namespace geonet
{

const Lifetime Lifetime::zero()
{
    return Lifetime();
}

Lifetime::Lifetime()
{
    set(Base::Fifty_Milliseconds, 0);
}

Lifetime::Lifetime(Base base, BitNumber<uint8_t, 6> multiplier)
{
    set(base, multiplier);
}

void Lifetime::set(Base base, BitNumber<uint8_t, 6> multiplier)
{
    m_lifetime = multiplier.raw() << 2 | (static_cast<uint8_t>(base) & base_mask);
}

bool Lifetime::operator<(const Lifetime& other) const
{
    return this->decode() < other.decode();
}

bool Lifetime::operator==(const Lifetime& other) const
{
    const units::Duration diff = this->decode() - other.decode();
    // 50 ms is the smallest non-zero value Lifetime can represent
    const auto min_value = 0.050 * units::si::seconds;
    return abs(diff) < min_value;
}

void Lifetime::encode(units::Duration duration)
{
    double seconds = duration / boost::units::si::seconds;
    if (seconds >= 630.0) {
        set(Base::Hundred_Seconds, std::lround(seconds / 100.0));
    } else if (seconds >= 63.0) {
        set(Base::Ten_Seconds, std::lround(seconds / 10.0));
    } else if (seconds >= 3.15) {
        set(Base::One_Second, std::lround(seconds));
    } else {
        set(Base::Fifty_Milliseconds, std::lround(seconds / 0.050));
    }
}

units::Duration Lifetime::decode() const
{
    using vanetza::units::si::seconds;
    Base base = static_cast<Base>(m_lifetime & base_mask);
    const double multiplier = (m_lifetime & multiplier_mask) >> 2;
    units::Duration unit;

    switch (base) {
        case Base::Fifty_Milliseconds:
            unit = 0.050 * seconds;
            break;
        case Base::One_Second:
            unit = 1.0 * seconds;
            // already done
            break;
        case Base::Ten_Seconds:
            unit = 10.0 * seconds;
            break;
        case Base::Hundred_Seconds:
            unit = 100.0 * seconds;
            break;
        default:
            throw std::runtime_error("Decoding of Lifetime::Base failed");
            break;
    };

    return multiplier * unit;
}

void serialize(const Lifetime& lifetime, OutputArchive& ar)
{
    serialize(host_cast(lifetime.raw()), ar);
}

void deserialize(Lifetime& lifetime, InputArchive& ar)
{
    uint8_t raw;
    deserialize(raw, ar);
    lifetime.raw(raw);
}

} // namespace geonet
} // namespace vanetza

