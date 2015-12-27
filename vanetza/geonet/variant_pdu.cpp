#include <vanetza/geonet/variant_pdu.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace geonet
{

BasicHeader& VariantPdu::basic()
{
    return m_basic;
}

const BasicHeader& VariantPdu::basic() const
{
    return m_basic;
}

CommonHeader& VariantPdu::common()
{
    return m_common;
}

const CommonHeader& VariantPdu::common() const
{
    return m_common;
}

HeaderVariant& VariantPdu::extended_variant()
{
    return m_extended;
}

HeaderConstRefVariant VariantPdu::extended_variant() const
{
    return m_extended;
}

VariantPdu::SecuredMessage* VariantPdu::secured()
{
    return m_secured.get_ptr();
}

const VariantPdu::SecuredMessage* VariantPdu::secured() const
{
    return m_secured.get_ptr();
}

void VariantPdu::secured(SecuredMessage* smsg)
{
    m_secured = boost::optional<SecuredMessage>(smsg, *smsg);
}

void VariantPdu::secured(SecuredMessage&& smsg)
{
    m_secured = std::move(smsg);
}

Pdu* VariantPdu::clone() const
{
    return new VariantPdu(*this);
}

} // namespace geonet
} // namespace vanetza
