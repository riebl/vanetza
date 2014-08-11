#ifndef ASN1C_CONVERSION_HPP_9E5QN6UC
#define ASN1C_CONVERSION_HPP_9E5QN6UC

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/common/byte_buffer_convertible.hpp>

namespace vanetza
{
namespace convertible
{
namespace asn1
{

template<class T>
struct byte_buffer_impl : public byte_buffer
{
    typedef T wrapper_type;

    byte_buffer_impl(wrapper_type&& t) :
        m_wrapper(std::move(t)) {}

    void convert(ByteBuffer& buffer) const override
    {
        buffer = m_wrapper.encode();
    }

    std::unique_ptr<byte_buffer> duplicate() const override
    {
        return std::unique_ptr<byte_buffer> {
            new vanetza::convertible::byte_buffer_impl<wrapper_type> {
                wrapper_type(m_wrapper)
            }
        };
    }

    std::size_t size() const override
    {
        return m_wrapper.size();
    }

    wrapper_type m_wrapper;
};

} // namespace asn1
} // namespace convertible
} // namespace vanetza

#endif /* ASN1C_CONVERSION_HPP_9E5QN6UC */

