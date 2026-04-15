#pragma once
#include <cstdint>
#include <functional>

namespace vanetza
{
namespace geodesy
{

/**
 * Standard country or area codes for statistical use by M49 standard.
 * \see https://unstats.un.org/unsd/methodology/m49/
 */
class M49Code
{
public:
    explicit constexpr M49Code(uint16_t value) : m_value(value) {}
    constexpr uint16_t value() const { return m_value; }

    bool operator==(M49Code other) const { return m_value == other.m_value; }
    bool operator!=(M49Code other) const { return m_value != other.m_value; }

private:
    uint16_t m_value;
};

} // namespace geodesy
} // namespace vanetza

namespace std
{
template<>
struct hash<vanetza::geodesy::M49Code>
{
    std::size_t operator()(vanetza::geodesy::M49Code code) const
    {
        return std::hash<uint16_t>{}(code.value());
    }
};

template<>
struct less<vanetza::geodesy::M49Code>
{
    bool operator()(vanetza::geodesy::M49Code a, vanetza::geodesy::M49Code b) const
    {
        return a.value() < b.value();
    }
};
} // namespace std
