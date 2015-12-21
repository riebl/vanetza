#ifndef EXTENDED_PDU_HPP_TL2WFH9W
#define EXTENDED_PDU_HPP_TL2WFH9W

#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/pdu.hpp>
#include <vanetza/geonet/serialization.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/security/secured_message.hpp>
#include <boost/iostreams/stream.hpp>

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
void serialize_for_signing(const ExtendedPdu<HEADER>& pdu, OutputArchive& ar);

template<class HEADER>
class ExtendedPduRefs;

template<class HEADER>
void serialize(const ExtendedPduRefs<HEADER>&, OutputArchive&);


template<class HEADER>
class ExtendedPdu : public Pdu
{
public:
    using SecuredMessage = security::SecuredMessage;

    ExtendedPdu() {}
    ExtendedPdu(const MIB& mib) : m_basic(mib), m_common(mib) {}
    ExtendedPdu(const DataRequest& request, const MIB& mib) :
        m_basic(request, mib), m_common(request, mib) {}
    ExtendedPdu(const BasicHeader& basic, const CommonHeader& common, const HEADER& extended) :
        m_basic(basic), m_common(common), m_extended(extended) {}
    ExtendedPdu(const BasicHeader& basic, const CommonHeader& common, const HEADER& extended,
            const SecuredMessage& secured) :
        m_basic(basic), m_common(common), m_extended(extended), m_secured(secured) {}
    BasicHeader& basic() override { return m_basic; }
    const BasicHeader& basic() const override { return m_basic; }
    CommonHeader& common() override { return m_common; }
    const CommonHeader& common() const override { return m_common; }
    HEADER& extended() { return m_extended; }
    const HEADER& extended() const { return m_extended; }
    boost::optional<SecuredMessage>& secured() { return m_secured; }
    const boost::optional<SecuredMessage>& secured() const { return m_secured; }

    ExtendedPdu* clone() const override { return new ExtendedPdu(*this); }

    std::size_t length() const override
    {
        const std::size_t secured_length = m_secured ? get_size(*m_secured) : 0;

        return BasicHeader::length_bytes +
            secured_length +
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
    boost::optional<SecuredMessage> m_secured;
};

template<class HEADER>
class ExtendedPduRefs : public Pdu
{
public:
    using SecuredMessage = security::SecuredMessage;

    ExtendedPduRefs(BasicHeader& basic, CommonHeader& common, HEADER& extended) :
        mr_basic(basic), mr_common(common), mr_extended(extended), mp_secured(nullptr) {}
    ExtendedPduRefs(BasicHeader& basic, CommonHeader& common, HEADER& extended,
            SecuredMessage& secured) :
        mr_basic(basic), mr_common(common), mr_extended(extended), mp_secured(&secured) {}
    BasicHeader& basic() { return mr_basic; }
    const BasicHeader& basic() const { return mr_basic; }
    CommonHeader& common() { return mr_common; }
    const CommonHeader& common() const { return mr_common; }
    HEADER& extended() { return mr_extended; }
    const HEADER& extended() const { return mr_extended; }
    SecuredMessage* secured() { return mp_secured; }
    const SecuredMessage* secured() const { return mp_secured; }

    ExtendedPdu<HEADER>* clone() const
    {
        if (mp_secured) {
            return new ExtendedPdu<HEADER>(mr_basic, mr_common, mr_extended, *mp_secured);
        } else {
            return new ExtendedPdu<HEADER>(mr_basic, mr_common, mr_extended);
        }
    }

    std::size_t length() const
    {
        std::size_t length = BasicHeader::length_bytes + CommonHeader::length_bytes;
        length += HEADER::length_bytes;
        if (mp_secured) {
            length += get_size(*mp_secured);
        }
        return length;
    }

    void serialize(OutputArchive& ar) const
    {
        geonet::serialize(*this, ar);
    }

private:
    BasicHeader& mr_basic;
    CommonHeader& mr_common;
    HEADER& mr_extended;
    SecuredMessage* mp_secured;
};

template<class HEADER>
void serialize(const ExtendedPdu<HEADER>& pdu, OutputArchive& ar)
{
    serialize(pdu.basic(), ar);
    if (pdu.secured()) {
        serialize(ar, pdu.secured().get());
    } else {
        serialize(pdu.common(), ar);
        serialize(pdu.extended(), ar);
    }
}

template<class HEADER>
void serialize(const ExtendedPduRefs<HEADER>& pdu, OutputArchive& ar)
{
    serialize(pdu.basic(), ar);
    if (pdu.secured()) {
        serialize(ar, *pdu.secured());
    } else {
        serialize(pdu.common(), ar);
        serialize(pdu.extended(), ar);
    }
}

template<class HEADER>
ByteBuffer convert_for_signing(const ExtendedPdu<HEADER>& pdu)
{
    ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream, boost::archive::no_header);

    serialize(pdu.common(), ar);
    serialize(pdu.extended(), ar);

    return buf;
}

} // namespace geonet
} // namespace vanetza

#endif /* EXTENDED_PDU_HPP_TL2WFH9W */
