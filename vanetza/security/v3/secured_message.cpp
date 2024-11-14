#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/net/packet.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/secured_message.hpp>

#include <boost/iostreams/stream.hpp>
#include <boost/optional/optional.hpp>
#include <boost/variant/static_visitor.hpp>

// asn1c quirk
struct Vanetza_Security_Certificate : public Vanetza_Security_CertificateBase {};

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

const asn1::SignedData* get_signed_data(const asn1::EtsiTs103097Data* data)
{
    if (data && data->content && data->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        return data->content->choice.signedData;
    } else {
        return nullptr;
    }
}

const asn1::HeaderInfo* get_header_info(const asn1::EtsiTs103097Data* data)
{
    const asn1::SignedData* signed_data = get_signed_data(data);
    if (signed_data) {
        return &signed_data->tbsData->headerInfo;
    } else {
        return nullptr;
    }
}

HashedId8 make_hashed_id8(const asn1::HashedId8& asn)
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

ByteBuffer get_x_coordinate(const asn1::EccP256CurvePoint& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            return copy_octets(point.choice.compressed_y_0);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            return copy_octets(point.choice.compressed_y_1);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_x_only:
            return copy_octets(point.choice.x_only);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
            return copy_octets(point.choice.uncompressedP256.x);
            break;
        default:
            return ByteBuffer {};
            break;
    }
}

ByteBuffer get_x_coordinate(const asn1::EccP384CurvePoint& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0:
            return copy_octets(point.choice.compressed_y_0);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1:
            return copy_octets(point.choice.compressed_y_1);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_x_only:
            return copy_octets(point.choice.x_only);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384:
            return copy_octets(point.choice.uncompressedP384.x);
            break;
        default:
            return ByteBuffer {};
            break;
    }
}

void assign(OCTET_STRING_t* dst, const ByteBuffer& src)
{
    OCTET_STRING_fromBuf(dst, reinterpret_cast<const char*>(src.data()), src.size());
}

} // namespace

SecuredMessage SecuredMessage::with_signed_data()
{
    SecuredMessage secured_message;
    secured_message->protocolVersion = 3;
    secured_message->content = asn1::allocate<asn1::Ieee1609Dot2Content>();
    secured_message->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;
    secured_message->content->choice.signedData = asn1::allocate<asn1::SignedData>();
    secured_message->content->choice.signedData->tbsData = asn1::allocate<asn1:: ToBeSignedData>();
    secured_message->content->choice.signedData->tbsData->payload = asn1::allocate<asn1::SignedDataPayload>();
    secured_message->content->choice.signedData->tbsData->payload->data = asn1::allocate<asn1::Ieee1609Dot2Data>();
    secured_message->content->choice.signedData->tbsData->payload->data->protocolVersion = 3;
    secured_message->content->choice.signedData->tbsData->payload->data->content = asn1::allocate<asn1::Ieee1609Dot2Content>();
    secured_message->content->choice.signedData->tbsData->payload->data->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
    return secured_message;
}

SecuredMessage::SecuredMessage() :
    asn1::asn1c_oer_wrapper<asn1::EtsiTs103097Data>(asn_DEF_Vanetza_Security_EtsiTs103097Data)
{
}

uint8_t SecuredMessage::protocol_version() const
{
    return m_struct->protocolVersion;
}

ItsAid SecuredMessage::its_aid() const
{
    ItsAid aid = 0;
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        const asn1::SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data && signed_data->tbsData) {
            aid = signed_data->tbsData->headerInfo.psid;
        }
    }
    return aid;
}

void SecuredMessage::set_its_aid(ItsAid its_aid)
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        asn1::SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data && signed_data->tbsData) {
            signed_data->tbsData->headerInfo.psid = its_aid;
        }
    }
}

void SecuredMessage::set_generation_time(Time64 time)
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        if (m_struct->content->choice.signedData->tbsData->headerInfo.generationTime == nullptr) {
            m_struct->content->choice.signedData->tbsData->headerInfo.generationTime = asn1::allocate<asn1::Time64>();
        }
        asn_uint642INTEGER(m_struct->content->choice.signedData->tbsData->headerInfo.generationTime, time);
    }
}

void SecuredMessage::set_generation_location(const asn1::ThreeDLocation& location)
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        if (m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation == nullptr) {
            m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation = asn1::allocate<asn1::ThreeDLocation>();
        }
        m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation->latitude = location.latitude;
        m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation->longitude = location.longitude;
        m_struct->content->choice.signedData->tbsData->headerInfo.generationLocation->elevation = location.elevation;
    }
}

void SecuredMessage::set_inline_p2pcd_request(std::list<HashedId3> requests)
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        assert(m_struct->content->choice.signedData);
        assert(m_struct->content->choice.signedData->tbsData);

        if (m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest) {
            ASN_STRUCT_RESET(asn_DEF_Vanetza_Security_SequenceOfHashedId3,
                &m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest);
        }

        for (HashedId3 request : requests) {
            this->add_inline_p2pcd_request(request);
        }
    }
}

void SecuredMessage::add_inline_p2pcd_request(HashedId3 unknown_certificate_digest)
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        if (m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest == nullptr) {
            m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest = asn1::allocate<asn1::SequenceOfHashedId3>();
        }
        Vanetza_Security_HashedId3_t* asn_digest = OCTET_STRING_new_fromBuf(&asn_DEF_Vanetza_Security_HashedId3, 
                reinterpret_cast<char*>(unknown_certificate_digest.data()), unknown_certificate_digest.size());
        ASN_SEQUENCE_ADD(m_struct->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest, asn_digest);
    }
}

void SecuredMessage::set_dummy_signature()
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        asn1::SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data) {
            // Reset the signature structure
            ASN_STRUCT_RESET(asn_DEF_Vanetza_Security_Signature, &(signed_data->signature));

            // Set the signature type to ECDSA NIST P256
            signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;

            // Initialize rSig part of the signature
            signed_data->signature.choice.ecdsaNistP256Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
            std::vector<uint8_t> dummy_r(32, 0); // Correct length for P256 signature part
            dummy_r[0] = 0; // Ensure the leading byte is set to zero if needed
            assign(&signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only, dummy_r);

            // Initialize sSig part of the signature
            std::vector<uint8_t> dummy_s(32, 0); // Correct length for P256 signature part
            assign(&signed_data->signature.choice.ecdsaNistP256Signature.sSig, dummy_s);
        }
    }
}

void SecuredMessage::set_signature(const Signature& signature)
{
    if (m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
        asn1::SignedData* signed_data = m_struct->content->choice.signedData;
        if (signed_data) {
            // Reset the signature structure
            ASN_STRUCT_RESET(asn_DEF_Vanetza_Security_Signature, &(signed_data->signature));

            // Set the signature type to ECDSA NIST P256
            switch (signature.type)
            {
            case vanetza::security::KeyType::NistP256:
                signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
                // Initialize rSig and sSig part of the signature

                // Check the type (x_only, y-1, y-0 or uncompressed ??????)
                signed_data->signature.choice.ecdsaNistP256Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
                assign(&signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only, signature.r);
                assign(&signed_data->signature.choice.ecdsaNistP256Signature.sSig, signature.s);
                break;
            case vanetza::security::KeyType::BrainpoolP256r1 :
                signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature;
                // Check the type (x_only, y-1, y-0 or uncompressed ??????)
                signed_data->signature.choice.ecdsaBrainpoolP256r1Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
                assign(&signed_data->signature.choice.ecdsaBrainpoolP256r1Signature.rSig.choice.x_only, signature.r);
                assign(&signed_data->signature.choice.ecdsaBrainpoolP256r1Signature.sSig, signature.s);
                break;
            case vanetza::security::KeyType::BrainpoolP384r1 :
                signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature;
                // Check the type (x_only, y-1, y-0 or uncompressed ??????)
                signed_data->signature.choice.ecdsaBrainpoolP384r1Signature.rSig.present = Vanetza_Security_EccP384CurvePoint_PR_x_only;
                assign(&signed_data->signature.choice.ecdsaBrainpoolP384r1Signature.rSig.choice.x_only, signature.r);
                assign(&signed_data->signature.choice.ecdsaBrainpoolP384r1Signature.sSig, signature.s);
                break;
            default:
                this->set_dummy_signature();
                break;
            }
        }
    }
}

void SecuredMessage::set_signature(const SomeEcdsaSignature& signature)
{
    struct ecc_point_visitor : public boost::static_visitor<asn1::EccP256CurvePoint> {
        asn1::EccP256CurvePoint operator()(const X_Coordinate_Only& x_only) const
        {
            asn1::EccP256CurvePoint* to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
            assign(&to_return->choice.x_only, x_only.x);
            return *to_return;
        }
        asn1::EccP256CurvePoint operator()(const Compressed_Lsb_Y_0& y0) const
        {
            asn1::EccP256CurvePoint* to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
            assign(&to_return->choice.compressed_y_0, y0.x);
            return *to_return;
        }
        asn1::EccP256CurvePoint operator()(const Compressed_Lsb_Y_1& y1) const
        {
            asn1::EccP256CurvePoint* to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
            assign(&to_return->choice.compressed_y_1, y1.x);
            return *to_return;
        }
        asn1::EccP256CurvePoint operator()(const Uncompressed& unc) const
        {
            asn1::EccP256CurvePoint* to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
            assign(&to_return->choice.uncompressedP256.x, unc.x);
            assign(&to_return->choice.uncompressedP256.y, unc.y);
            return *to_return;
        }
    };

    struct signature_visitor : public boost::static_visitor<asn1::Signature>
    {
        asn1::Signature operator()(const EcdsaSignature& signature) const
        {
            asn1::Signature* final_signature = asn1::allocate<asn1::Signature>();
            final_signature->present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
            assign(&final_signature->choice.ecdsaNistP256Signature.sSig, signature.s);
            final_signature->choice.ecdsaNistP256Signature.rSig = boost::apply_visitor(
                ecc_point_visitor(),
                signature.R
            );
            return *final_signature;
        }

        asn1::Signature operator()(const EcdsaSignatureFuture& signature) const
        {
            return this->operator()(signature.get());
        }
    };

    m_struct->content->choice.signedData->signature = boost::apply_visitor(signature_visitor(), signature);
}

PacketVariant SecuredMessage::payload() const
{
    ByteBuffer buffer;
    switch (m_struct->content->present) {
        case Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData:
            buffer = get_payload(&m_struct->content->choice.unsecuredData);
            break;
        case Vanetza_Security_Ieee1609Dot2Content_PR_signedData:
            buffer = get_payload(m_struct->content->choice.signedData);
            break;
        default:
            // empty buffer as fallback
            break;
    }

    return CohesivePacket { std::move(buffer), OsiLayer::Network };
}

void SecuredMessage::set_payload(const ByteBuffer& payload)
{
    switch (m_struct->content->present) {
        case Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData:
            vanetza::security::v3::set_payload(&m_struct->content->choice.unsecuredData, payload);
            break;
        case Vanetza_Security_Ieee1609Dot2Content_PR_signedData:
            vanetza::security::v3::set_payload(&m_struct->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData, payload);
            break;
        default:
          // cannot copy payload into secured message
          break;
    }
}

HashAlgorithm SecuredMessage::hash_id() const
{
    HashAlgorithm algo = HashAlgorithm::Unspecified;

    const asn1::SignedData* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        switch (signed_data->hashId) {
            case Vanetza_Security_HashAlgorithm_sha256:
                algo = HashAlgorithm::SHA256;
                break;
            case Vanetza_Security_HashAlgorithm_sha384:
                algo = HashAlgorithm::SHA384;
                break;
            default:
                break;
        }
    }

    return algo;
}

void SecuredMessage::set_hash_id(HashAlgorithm hash)
{
    assert(m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData);
    switch (hash) {
        case HashAlgorithm::SHA256:
            m_struct->content->choice.signedData->hashId = Vanetza_Security_HashAlgorithm_sha256;
            break;
        case HashAlgorithm::SHA384:
            m_struct->content->choice.signedData->hashId = Vanetza_Security_HashAlgorithm_sha384;
            break;
        default:
            m_struct->content->choice.signedData->hashId = -1;
    }
}

void SecuredMessage::set_signer_identifier(const HashedId8& digest)
{
    assert(m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData);
    asn1::SignerIdentifier* signer = &m_struct->content->choice.signedData->signer;
    ASN_STRUCT_RESET(asn_DEF_Vanetza_Security_SignerIdentifier, signer);
    signer->present = Vanetza_Security_SignerIdentifier_PR_digest;
    OCTET_STRING_fromBuf(&signer->choice.digest, reinterpret_cast<const char*>(digest.data()), digest.size());
}

void SecuredMessage::set_signer_identifier(const Certificate& cert)
{
    assert(m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData);
    asn1::SignerIdentifier* signer = &m_struct->content->choice.signedData->signer;
    ASN_STRUCT_RESET(asn_DEF_Vanetza_Security_SignerIdentifier, signer);
    signer->present = Vanetza_Security_SignerIdentifier_PR_certificate;
    ASN_SEQUENCE_ADD(&signer->choice.certificate, asn1::copy(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, cert.content()));
}

bool SecuredMessage::is_signed() const
{
    return m_struct->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData;
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
    const asn1::SignedData* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        const asn1::Signature& asn = signed_data->signature;
        Signature sig;
        switch (asn.present)
        {
            case Vanetza_Security_Signature_PR_ecdsaNistP256Signature:
                sig.type = KeyType::NistP256;
                sig.r = get_x_coordinate(asn.choice.ecdsaNistP256Signature.rSig);
                sig.s = copy_octets(asn.choice.ecdsaNistP256Signature.sSig);
                break;
            case Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature:
                sig.type = KeyType::BrainpoolP256r1;
                sig.r = get_x_coordinate(asn.choice.ecdsaBrainpoolP256r1Signature.rSig);
                sig.s = copy_octets(asn.choice.ecdsaBrainpoolP256r1Signature.sSig);
                break;
            case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
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
    const asn1::SignedData* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        if (signed_data->signer.present == Vanetza_Security_SignerIdentifier_PR_digest) {
            const asn1::HashedId8* digest = &signed_data->signer.choice.digest;
            return digest;
        } else if (signed_data->signer.present == Vanetza_Security_SignerIdentifier_PR_certificate) {
            const asn1::SequenceOfCertificate& certificates = signed_data->signer.choice.certificate;
            // TS 103 097 v1.3.1 contraints this to exactly one certificate in clause 5.2
            if (certificates.list.count == 1) {
                const asn1::Certificate* cert = certificates.list.array[0];
                return cert;
            }
        }
    }

    return static_cast<asn1::HashedId8*>(nullptr);
}

ByteBuffer SecuredMessage::signing_payload() const
{
    const asn1::SignedData* signed_data = get_signed_data(m_struct);
    if (signed_data) {
        return asn1::encode_oer(asn_DEF_Vanetza_Security_ToBeSignedData, signed_data->tbsData);
    } else {
        return ByteBuffer {};
    }
}

void SecuredMessage::set_requested_certificate(const Certificate& cert)
{
    const asn1::SignedData* signed_data = get_signed_data(m_struct);
    if (signed_data && signed_data->tbsData) {
        if (signed_data->tbsData->headerInfo.requestedCertificate) {
            ASN_STRUCT_FREE(asn_DEF_Vanetza_Security_Certificate, signed_data->tbsData->headerInfo.requestedCertificate);
        }
        signed_data->tbsData->headerInfo.requestedCertificate =
            static_cast<Vanetza_Security_Certificate*>(asn1::copy(asn_DEF_Vanetza_Security_Certificate, cert.content()));
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

ByteBuffer get_payload(const asn1::Opaque* unsecured)
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

void set_payload(asn1::Opaque* unsecured, const ByteBuffer& buffer)
{
    unsecured->size = buffer.size();
    unsecured->buf = new uint8_t[unsecured->size]; // Allocate memory for the buffer
    std::copy(buffer.begin(), buffer.end(), unsecured->buf);
}

ByteBuffer get_payload(const asn1::SignedData* signed_data)
{
    ByteBuffer buffer;
    if (signed_data->tbsData && signed_data->tbsData->payload) {
        const asn1::SignedDataPayload* signed_payload = signed_data->tbsData->payload;
        if (signed_payload->data && signed_payload->data->content) {
            const asn1::Ieee1609Dot2Content* content = signed_payload->data->content;
            if (content->present == Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData) {
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
        result_type operator()(const asn1::HashedId8* digest) const
        {
            return digest ? make_hashed_id8(*digest) : result_type { };
        }

        result_type operator()(const asn1::Certificate* cert) const
        {
            return cert ? calculate_digest(*cert) : result_type { };
        }
    };
    return boost::apply_visitor(cert_id_visitor(), identifier);
}

bool contains_certificate(const SecuredMessage::SignerIdentifier& identifier)
{
    struct visitor : public boost::static_visitor<bool> {
        bool operator()(const asn1::HashedId8* digest) const
        {
            return false;
        }

        bool operator()(const asn1::Certificate* cert) const
        {
            return true;
        }
    };
    return boost::apply_visitor(visitor(), identifier);
}

} // namespace v3
} // namespace security
} // namespace vanetza
