#ifndef QUANTITY_H_UV67B0JT
#define QUANTITY_H_UV67B0JT

template<typename T>
class Quantity
{
    public:
    explicit Quantity(const T& value) : m_value(value) {}

    T value() const { return m_value; }

    private:
    T m_value;
};

#endif /* QUANTITY_H_UV67B0JT */

