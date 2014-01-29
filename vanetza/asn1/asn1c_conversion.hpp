#ifndef ASN1C_CONVERSION_HPP_9E5QN6UC
#define ASN1C_CONVERSION_HPP_9E5QN6UC

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/common/byte_buffer_convertible.hpp>

namespace vanetza
{
namespace convertible
{

template<class T>
struct byte_buffer_impl<asn1::asn1c_wrapper<T>&&> : public byte_buffer
{
    byte_buffer_impl(asn1::asn1c_wrapper<T>&& t) :
        m_wrapper(std::move(t)) {}

    void convert(ByteBuffer& buffer) const override
    {
        buffer = m_wrapper.encode();
    }

    std::size_t size() const override
    {
        return m_wrapper.size();
    }

    asn1::asn1c_wrapper<T> m_wrapper;
};

} // namespace convertible
} // namespace vanetza

#endif /* ASN1C_CONVERSION_HPP_9E5QN6UC */

