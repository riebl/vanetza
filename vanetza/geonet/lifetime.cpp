#include "lifetime.hpp"
#include <cmath>
#include <stdexcept>

namespace vanetza
{
namespace geonet
{

Lifetime::Lifetime()
{
    set(Base::_50_MS, 0);
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
    const double diff = this->decode() - other.decode();
    const double min_value = 0.050; // 50 ms is lowest non-zero value
    return std::abs(diff) < min_value;
}

void Lifetime::encode(double seconds)
{
    if (seconds >= 630.0) {
        set(Base::_100_S, std::lround(seconds / 100.0));
    } else if (seconds >= 63.0) {
        set(Base::_10_S, std::lround(seconds / 10.0));
    } else if (seconds >= 3.15) {
        set(Base::_1_S, std::lround(seconds));
    } else {
        set(Base::_50_MS, std::lround(seconds / 0.050));
    }
}

double Lifetime::decode() const
{
    Base base = static_cast<Base>(m_lifetime & base_mask);
    double lifetime = (m_lifetime & multiplier_mask) >> 2;

    switch (base) {
        case Base::_50_MS:
            lifetime *= 0.050;
            break;
        case Base::_1_S:
            // already done
            break;
        case Base::_10_S:
            lifetime *= 10.0;
            break;
        case Base::_100_S:
            lifetime *= 100.0;
            break;
        default:
            lifetime = -1.0;
            throw std::runtime_error("Decoding of Lifetime::Base failed");
            break;
    };

    return lifetime;
}

} // namespace geonet
} // namespace vanetza

