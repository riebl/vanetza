#ifndef QUANTITY_HPP_UV67B0JT
#define QUANTITY_HPP_UV67B0JT

namespace vanetza
{

template<typename T>
class Quantity
{
    public:
    typedef T value_type;

    explicit Quantity(const T& value) : m_value(value) {}
    T value() const { return m_value; }

    private:
    T m_value;
};

} // namespace vanetza

#endif /* QUANTITY_HPP_UV67B0JT */

