#ifndef EXTENDED_PDU_HPP_TL2WFH9W
#define EXTENDED_PDU_HPP_TL2WFH9W

#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/pdu.hpp>
#include <vanetza/geonet/serialization.hpp>

namespace vanetza
{
namespace geonet
{

// various forward declarations
template<class HEADER>
class ExtendedPdu;

template<class HEADER>
void serialize(const ExtendedPdu<HEADER>&, OutputArchive&);

template<class HEADER>
class ExtendedPdu : public Pdu
{
public:
    ExtendedPdu() {}
    ExtendedPdu(const MIB& mib) : m_basic(mib), m_common(mib) {}
    ExtendedPdu(const DataRequest& request, const MIB& mib) :
        m_basic(request, mib), m_common(request, mib) {}
    ExtendedPdu(const BasicHeader& basic, const CommonHeader& common, const HEADER& extended) :
        m_basic(basic), m_common(common), m_extended(extended) {}
    BasicHeader& basic() override { return m_basic; }
    const BasicHeader& basic() const override { return m_basic; }
    CommonHeader& common() override { return m_common; }
    const CommonHeader& common() const override { return m_common; }
    HEADER& extended() { return m_extended; }
    const HEADER& extended() const { return m_extended; }

    ExtendedPdu* clone() const override { return new ExtendedPdu(*this); }

    std::size_t length() const override
    {
        return BasicHeader::length_bytes +
            CommonHeader::length_bytes +
            HEADER::length_bytes;
    }

    void serialize(OutputArchive& ar) const override
    {
        geonet::serialize(*this, ar);
    }

private:
    BasicHeader m_basic;
    CommonHeader m_common;
    HEADER m_extended;
};

template<class HEADER>
void serialize(const ExtendedPdu<HEADER>& pdu, OutputArchive& ar)
{
    serialize(pdu.basic(), ar);
    serialize(pdu.common(), ar);
    serialize(pdu.extended(), ar);
}

} // namespace geonet
} // namespace vanetza

#endif /* EXTENDED_PDU_HPP_TL2WFH9W */

