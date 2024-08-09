#include <vanetza/net/packet.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/variant/static_visitor.hpp>
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

void SecuredMessage::set_its_aid(ItsAid its_aid) {
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
        SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data && signed_data->tbsData) {
            signed_data->tbsData->headerInfo.psid = its_aid;
        }
    }
}

void SecuredMessage::set_generation_time(Time64 time) {
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
        if (m_struct->content->choice.signedData->tbsData->headerInfo.generationTime == nullptr) {
            //generationTime is not initialiazed
            m_struct->content->choice.signedData->tbsData->headerInfo.generationTime = static_cast<Time64_t*>(calloc(1, sizeof(Time64_t)));;
        }
        asn_uint642INTEGER(
            (m_struct->content->choice.signedData->tbsData->headerInfo.generationTime),
            time
    );
    }
}

void SecuredMessage::set_generation_location(ThreeDLocation location) {
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
        if (m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation == nullptr) {
            //generationLocation is not initialiazed
            m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation = static_cast<ThreeDLocation_t*>(calloc(1, sizeof(ThreeDLocation_t)));;
        }
        m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation->latitude = location.latitude;
        m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation->longitude = location.longitude;
        m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation->elevation = location.elevation;
    }
}


void SecuredMessage::set_inline_p2pcd_request(std::list<HashedId3> requests){
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(
            asn_DEF_SequenceOfHashedId3,
            &(m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest)
        );
        for (HashedId3 request : requests) {
            this->add_inline_p2_pcd_request(request);
        }
    }

}

void SecuredMessage::add_inline_p2_pcd_request(HashedId3 unkown_certificate_digest) {
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
            if (m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest == nullptr) {
            //generationTime is not initialiazed
            m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest = static_cast<SequenceOfHashedId3*>(calloc(1, sizeof(SequenceOfHashedId3)));;
        }
        ASN_SEQUENCE_ADD(&(m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest), &unkown_certificate_digest);
    }
}

void SecuredMessage::set_dummy_signature() {
    if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
        SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data) {
            // Reset the signature structure
            ASN_STRUCT_RESET(asn_DEF_Signature, &(signed_data->signature));

            // Set the signature type to ECDSA NIST P256
            signed_data->signature.present = Signature_PR_ecdsaNistP256Signature;

            // Initialize rSig part of the signature
            signed_data->signature.choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR_x_only;
            std::vector<uint8_t> dummy_r(32, 0); // Correct length for P256 signature part
            dummy_r[0] = 0; // Ensure the leading byte is set to zero if needed
            OCTET_STRING_fromBuf(
                &signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only,
                reinterpret_cast<const char*>(dummy_r.data()),
                dummy_r.size()
            );

            // Initialize sSig part of the signature
            std::vector<uint8_t> dummy_s(32, 0); // Correct length for P256 signature part
            OCTET_STRING_fromBuf(
                &signed_data->signature.choice.ecdsaNistP256Signature.sSig,
                reinterpret_cast<const char*>(dummy_s.data()),
                dummy_s.size()
            );
        }
    }
}

void SecuredMessage::set_signature(const Signature& signature) {
        if (m_struct->content->present == Ieee1609Dot2Content_PR_signedData) {
            SignedData* signed_data = m_struct->content->choice.signedData;
            if (signed_data) {
                // Reset the signature structure
                ASN_STRUCT_RESET(asn_DEF_Signature, &(signed_data->signature));

                // Set the signature type to ECDSA NIST P256
                switch (signature.type)
                {
                case vanetza::security::KeyType::NistP256:
                    signed_data->signature.present = Signature_PR_ecdsaNistP256Signature;
                    // Initialize rSig and sSig part of the signature

                    // Check the type (x_only, y-1, y-0 or uncompressed ??????)
                    signed_data->signature.choice.ecdsaNistP256Signature.rSig.present = EccP256CurvePoint_PR_x_only;
                    OCTET_STRING_fromBuf(
                        &signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only,
                        reinterpret_cast<const char*>(signature.r.data()),
                        signature.r.size()
                    );
                    OCTET_STRING_fromBuf(
                        &signed_data->signature.choice.ecdsaNistP256Signature.sSig,
                        reinterpret_cast<const char*>(signature.s.data()),
                        signature.s.size()
                    );
                    break;
                case vanetza::security::KeyType::BrainpoolP256r1 :
                    signed_data->signature.present = Signature_PR_ecdsaBrainpoolP256r1Signature;
                    // Check the type (x_only, y-1, y-0 or uncompressed ??????)
                    signed_data->signature.choice.ecdsaBrainpoolP256r1Signature.rSig.present = EccP256CurvePoint_PR_x_only;
                    OCTET_STRING_fromBuf(
                        &signed_data->signature.choice.ecdsaBrainpoolP256r1Signature.rSig.choice.x_only,
                        reinterpret_cast<const char*>(signature.r.data()),
                        signature.r.size()
                    );
                    OCTET_STRING_fromBuf(
                        &signed_data->signature.choice.ecdsaBrainpoolP256r1Signature.sSig,
                        reinterpret_cast<const char*>(signature.s.data()),
                        signature.s.size()
                    );
                    break;
                case vanetza::security::KeyType::BrainpoolP384r1 :
                    signed_data->signature.present = Signature_PR_ecdsaBrainpoolP384r1Signature;
                    // Check the type (x_only, y-1, y-0 or uncompressed ??????)
                    signed_data->signature.choice.ecdsaBrainpoolP384r1Signature.rSig.present = EccP384CurvePoint_PR_x_only;
                    OCTET_STRING_fromBuf(
                        &signed_data->signature.choice.ecdsaBrainpoolP384r1Signature.rSig.choice.x_only,
                        reinterpret_cast<const char*>(signature.r.data()),
                        signature.r.size()
                    );
                    OCTET_STRING_fromBuf(
                        &signed_data->signature.choice.ecdsaBrainpoolP384r1Signature.sSig,
                        reinterpret_cast<const char*>(signature.s.data()),
                        signature.s.size()
                    );
                    break;
                default:
                    this->set_dummy_signature();
                    break;
                }
            }
    }
}

void SecuredMessage::set_signature(const SomeEcdsaSignature& signature) {
    struct ecc_point_visitor : public boost::static_visitor<EccP256CurvePoint_t> {
        EccP256CurvePoint_t operator()(const X_Coordinate_Only& x_only) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_x_only;
            OCTET_STRING_fromBuf(
                &(to_return->choice.x_only),
                reinterpret_cast<const char*>(x_only.x.data()),
                x_only.x.size()
            );
            return *to_return;
        }
        EccP256CurvePoint_t operator()(const Compressed_Lsb_Y_0& y0) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_compressed_y_0;
            OCTET_STRING_fromBuf(
                &(to_return->choice.compressed_y_0),
                reinterpret_cast<const char*>(y0.x.data()),
                y0.x.size()
            );
            return *to_return;
        }
        EccP256CurvePoint_t operator()(const Compressed_Lsb_Y_1& y1) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_compressed_y_1;
            OCTET_STRING_fromBuf(
                &(to_return->choice.compressed_y_1),
                reinterpret_cast<const char*>(y1.x.data()),
                y1.x.size()
            );
            return *to_return;
        }
        EccP256CurvePoint_t operator()(const Uncompressed& unc) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_uncompressedP256;
            OCTET_STRING_fromBuf(
                &(to_return->choice.uncompressedP256.x),
                reinterpret_cast<const char*>(unc.x.data()),
                unc.x.size()
            );
            OCTET_STRING_fromBuf(
                &(to_return->choice.uncompressedP256.y),
                reinterpret_cast<const char*>(unc.y.data()),
                unc.y.size()
            );
            return *to_return;
        }
    };
    struct signature_visitor : public boost::static_visitor<Signature_t>
    {
        Signature_t operator()(const EcdsaSignature& signature) const
        {
            Signature_t* final_signature = static_cast<Signature_t*>(vanetza::asn1::allocate(sizeof(Signature_t)));
            final_signature->present = Signature_PR_ecdsaNistP256Signature;
            OCTET_STRING_fromBuf(
                &(final_signature->choice.ecdsaNistP256Signature.sSig),
                reinterpret_cast<const char*>(signature.s.data()),
                signature.s.size()
            );
            final_signature->choice.ecdsaNistP256Signature.rSig = boost::apply_visitor(
                ecc_point_visitor(),
                signature.R
            );
            return *final_signature;
        }
        Signature_t operator()(const EcdsaSignatureFuture& signature) const
        {
            Signature_t final_signature;
/*             EcdsaSignature temp = signature.get();
            final_signature = boost::apply_visitor(signature_visitor(), temp); */
            return final_signature;
        }
    };
    m_struct->content->choice.signedData->signature = boost::apply_visitor(signature_visitor(), signature);
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

void SecuredMessage::set_payload(ByteBuffer& payload) {
    switch (m_struct->content->present) {
        case Ieee1609Dot2Content_PR_unsecuredData:
            vanetza::security::v3::set_payload(&m_struct->content->choice.unsecuredData, payload);
            break;
        case Ieee1609Dot2Content_PR_signedData:
            vanetza::security::v3::set_payload(&m_struct->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData, payload);
            break;
    }

}

void SecuredMessage::set_signer_identifier(const HashedId8& digest)
{
    assert(m_struct->content->present == Ieee1609Dot2Content_PR_signedData);
    SignerIdentifier_t* signer = &m_struct->content->choice.signedData->signer;
    ASN_STRUCT_RESET(asn_DEF_SignerIdentifier, signer);
    signer->present = SignerIdentifier_PR_digest;
    OCTET_STRING_fromBuf(&signer->choice.digest, reinterpret_cast<const char*>(digest.data()), digest.size());
}

void SecuredMessage::set_signer_identifier(const Certificate& cert)
{
    assert(m_struct->content->present == Ieee1609Dot2Content_PR_signedData);
    SignerIdentifier_t* signer = &m_struct->content->choice.signedData->signer;
    ASN_STRUCT_RESET(asn_DEF_SignerIdentifier, signer);
    signer->present = SignerIdentifier_PR_certificate;
    ASN_SEQUENCE_ADD(&signer->choice.certificate, asn1::copy(asn_DEF_EtsiTs103097Certificate, cert.content()));
}

ByteBuffer SecuredMessage::convert_for_signing()
{
    vanetza::ByteBuffer to_return;
    try {
        to_return = vanetza::asn1::encode_oer(asn_DEF_ToBeSignedData, m_struct->content->choice.signedData->tbsData);
    } catch(std::runtime_error& er) {
    }
    return to_return;
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

ByteBuffer convert_to_payload(vanetza::DownPacket packet)
{
    ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

    serialize(ar, packet);

    stream.close();
    return buf;
}

void set_payload(Opaque_t* unsecured, const ByteBuffer& buffer)
{
    unsecured->size = buffer.size();
    unsecured->buf = new uint8_t[unsecured->size]; // Allocate memory for the buffer
    std::copy(buffer.begin(), buffer.end(), unsecured->buf);
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
