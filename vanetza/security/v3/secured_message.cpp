#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <iterator>
#include <boost/optional/optional.hpp>

// asn1c quirk
struct Certificate : public CertificateBase {};

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

const SignedData_t* get_signed_data(const EtsiTs103097Data_t* data)
{
    if (data && data->content && data->content->present == Ieee1609Dot2Content_PR_signedData) {
        return data->content->choice.signedData;
    } else {
        return nullptr;
    }
}

const HeaderInfo_t* get_header_info(const EtsiTs103097Data_t* data)
{
    const SignedData_t* signed_data = get_signed_data(data);
    if (signed_data) {
        return &signed_data->tbsData->headerInfo;
    } else {
        return nullptr;
    }
}

HashedId8 make_hashed_id8(const HashedId8_t& asn)
{
    HashedId8 result;
    std::copy_n(asn.buf, std::min(asn.size, result.size()), result.data());
    return result;
}

ByteBuffer copy_octets(const OCTET_STRING_t& octets)
{
    ByteBuffer buffer(octets.size);
    std::memcpy(buffer.data(), octets.buf, octets.size);
    return buffer;
}

ByteBuffer get_x_coordinate(const EccP256CurvePoint_t& point)
{
    switch (point.present) {
        case EccP256CurvePoint_PR_compressed_y_0:
            return copy_octets(point.choice.compressed_y_0);
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            return copy_octets(point.choice.compressed_y_1);
            break;
        case EccP256CurvePoint_PR_x_only:
            return copy_octets(point.choice.x_only);
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            return copy_octets(point.choice.uncompressedP256.x);
            break;
        default:
            return ByteBuffer {};
            break;
    }
}

ByteBuffer get_x_coordinate(const EccP384CurvePoint_t& point)
{
    switch (point.present) {
        case EccP384CurvePoint_PR_compressed_y_0:
            return copy_octets(point.choice.compressed_y_0);
            break;
        case EccP384CurvePoint_PR_compressed_y_1:
            return copy_octets(point.choice.compressed_y_1);
            break;
        case EccP384CurvePoint_PR_x_only:
            return copy_octets(point.choice.x_only);
            break;
        case EccP384CurvePoint_PR_uncompressedP384:
            return copy_octets(point.choice.uncompressedP384.x);
            break;
        default:
            return ByteBuffer {};
            break;
    }
}

} // namespace

SecuredMessage::SecuredMessage() :
    asn1::asn1c_oer_wrapper<EtsiTs103097Data_t>(asn_DEF_EtsiTs103097Data)
{
}

uint8_t SecuredMessage::protocol_version() const
{
    return m_struct->protocolVersion;
}

ItsAid SecuredMessage::its_aid() const
{
    ItsAid aid = 0;
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
        const SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data && signed_data->tbsData) {
            aid = signed_data->tbsData->headerInfo.psid;
        }
    }
    return aid;
}

PacketVariant SecuredMessage::payload() const
{
    ByteBuffer buffer;
    switch (m_struct->content->present) {
        case Ieee1609Dot2Content_PR_unsecuredData:
            buffer = get_payload(&m_struct->content->choice.unsecuredData);
            break;
        case Ieee1609Dot2Content_PR_signedData:
            buffer = get_payload(m_struct->content->choice.signedData);
            break;
    }

    return CohesivePacket { std::move(buffer), OsiLayer::Network };
}

bool SecuredMessage::is_signed() const
{
    return m_struct->content->present == Ieee1609Dot2Content_PR_signedData;
}

boost::optional<SecuredMessage::Time64> SecuredMessage::generation_time() const
{
    boost::optional<Time64> gen_time;
    auto header_info = get_header_info(m_struct);
    if (header_info) {
        std::uintmax_t tmp;
        if (asn_INTEGER2umax(header_info->generationTime, &tmp) == 0) {
            gen_time = tmp;
        }
    }
    return gen_time;
}

boost::optional<Signature> SecuredMessage::signature() const
{
    const SignedData_t* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        const Signature_t& asn = signed_data->signature;
        Signature sig;
        switch (asn.present)
        {
            case Signature_PR_ecdsaNistP256Signature:
                sig.type = KeyType::NistP256;
                sig.r = get_x_coordinate(asn.choice.ecdsaNistP256Signature.rSig);
                sig.s = copy_octets(asn.choice.ecdsaNistP256Signature.sSig);
                break;
            case Signature_PR_ecdsaBrainpoolP256r1Signature:
                sig.type = KeyType::BrainpoolP256r1;
                sig.r = get_x_coordinate(asn.choice.ecdsaBrainpoolP256r1Signature.rSig);
                sig.s = copy_octets(asn.choice.ecdsaBrainpoolP256r1Signature.sSig);
                break;
            case Signature_PR_ecdsaBrainpoolP384r1Signature:
                sig.type = KeyType::BrainpoolP384r1;
                sig.r = get_x_coordinate(asn.choice.ecdsaBrainpoolP384r1Signature.rSig);
                sig.s = copy_octets(asn.choice.ecdsaBrainpoolP384r1Signature.sSig);
                break;
            default:
                return boost::none;
        }
        return sig;
    }

    return boost::none;
}

SecuredMessage::SignerIdentifier SecuredMessage::signer_identifier() const
{
    const SignedData_t* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        if (signed_data->signer.present == SignerIdentifier_PR_digest) {
            return &signed_data->signer.choice.digest;
        } else if (signed_data->signer.present == SignerIdentifier_PR_certificate) {
            const SequenceOfCertificate_t& certificates = signed_data->signer.choice.certificate;
            // TS 103 097 v1.3.1 contraints this to exactly one certificate in clause 5.2
            if (certificates.list.count == 1) {
                const Certificate_t* cert = certificates.list.array[0];
                return cert;
            }
        }
    }

    return static_cast<HashedId8_t*>(nullptr);
}

ByteBuffer SecuredMessage::signing_payload() const
{
    const SignedData_t* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        return asn1::encode_oer(asn_DEF_ToBeSignedData, signed_data->tbsData);
    } else {
        return ByteBuffer {};
    }
}

size_t get_size(const SecuredMessage& message)
{
    return message.size();
}

void serialize(OutputArchive& ar, const SecuredMessage& msg)
{
    ByteBuffer buffer = msg.encode();
    ar.save_binary(buffer.data(), buffer.size());
}

size_t deserialize(InputArchive& ar, SecuredMessage& msg)
{
    std::size_t len = ar.remaining_bytes();
    // TODO optimize decoding step without buffer allocation
    ByteBuffer buffer;
    buffer.resize(len);
    ar.load_binary(buffer.data(), len);
    return msg.decode(buffer) ? len : 0;
}

ByteBuffer get_payload(const Opaque_t* unsecured)
{
    ByteBuffer buffer;
    buffer.reserve(unsecured->size);
    std::copy_n(unsecured->buf, unsecured->size, std::back_inserter(buffer));
    return buffer;
}

ByteBuffer get_payload(const SignedData* signed_data)
{
    ByteBuffer buffer;
    if (signed_data->tbsData && signed_data->tbsData->payload) {
        const SignedDataPayload_t* signed_payload = signed_data->tbsData->payload;
        if (signed_payload->data && signed_payload->data->content) {
            const Ieee1609Dot2Content_t* content = signed_payload->data->content;
            if (content->present == Ieee1609Dot2Content_PR_unsecuredData) {
                buffer = get_payload(&content->choice.unsecuredData);
            }
        }
    }
    return buffer;
}

boost::optional<HashedId8> get_certificate_id(const SecuredMessage::SignerIdentifier& identifier)
{
    using result_type = boost::optional<HashedId8>;
    struct cert_id_visitor : public boost::static_visitor<result_type> {
        result_type operator()(const HashedId8_t* digest) const
        {
            return digest ? make_hashed_id8(*digest) : result_type { };
        }

        result_type operator()(const Certificate_t* cert) const
        {
            return cert ? calculate_hash(*cert) : result_type { };
        }
    };
    return boost::apply_visitor(cert_id_visitor(), identifier);
}

} // namespace v3
} // namespace security
} // namespace vanetza
