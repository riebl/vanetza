#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/security/exception.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/serialization.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <boost/iostreams/stream.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <iomanip>
#include <fstream>
#include <iterator>

namespace vanetza
{
namespace security
{

HeaderField* SecuredMessage::header_field(HeaderFieldType type)
{
    HeaderField* match = nullptr;
    for (auto& field : header_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

const HeaderField* SecuredMessage::header_field(HeaderFieldType type) const
{
    const HeaderField* match = nullptr;
    for (auto& field : header_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

TrailerField* SecuredMessage::trailer_field(TrailerFieldType type)
{
    TrailerField* match = nullptr;
    for (auto& field : trailer_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

const TrailerField* SecuredMessage::trailer_field(TrailerFieldType type) const
{
    const TrailerField* match = nullptr;
    for (auto& field : trailer_fields) {
        if (get_type(field) == type) {
            match = &field;
            break;
        }
    }
    return match;
}

size_t get_size(const SecuredMessage& message)
{
    size_t size = sizeof(uint8_t); // protocol version
    size += get_size(message.header_fields);
    size += length_coding_size(get_size(message.header_fields));
    size += get_size(message.trailer_fields);
    size += length_coding_size(get_size(message.trailer_fields));
    size += get_size(message.payload);
    return size;
}

size_t get_size(const SecuredMessageV3& message)
{
    return message.get_size();
}

size_t get_size(const SecuredMessageVariant& message){
    struct canonical_visitor : public boost::static_visitor<size_t>
        {
            size_t operator()(const SecuredMessageV2& message) const
            {
                return get_size(message);
            }

            size_t operator()(const SecuredMessageV3& message) const
            {
                return get_size(message);
            }
        };
    return boost::apply_visitor(canonical_visitor(), message);
}


void serialize(OutputArchive& ar, const SecuredMessage& message)
{
    const uint8_t protocol_version = message.protocol_version();
    ar << protocol_version;
    serialize(ar, message.header_fields);
    serialize(ar, message.payload);
    serialize(ar, message.trailer_fields);
}

void serialize(OutputArchive& ar, const SecuredMessageV3& message)
{
    ByteBuffer temp = message.serialize();
    ar.save_binary(temp.data(), temp.size());
}

void serialize(OutputArchive& ar, const SecuredMessageVariant& message)
{
    class canonical_visitor : public boost::static_visitor<>
    {
        public:
            canonical_visitor(OutputArchive& ar): ar_(ar){}
            void operator()(const SecuredMessageV2& message) const
            {
                serialize(ar_,message);
            }

            void operator()(const SecuredMessageV3& message) const
            {
                serialize(ar_,message);
            }

            OutputArchive& ar_;
    };
    canonical_visitor visitor(ar);
    boost::apply_visitor(visitor, message);
}


size_t deserialize(InputArchive& ar, SecuredMessage& message)
{
    uint8_t protocol_version = 0;
    ar >> protocol_version;
    size_t length = sizeof(protocol_version);
    if (protocol_version == 2) {
        const size_t hdr_length = deserialize(ar, message.header_fields);
        length += hdr_length + length_coding_size(hdr_length);
        length += deserialize(ar, message.payload);
        const size_t trlr_length = deserialize(ar, message.trailer_fields);
        length += trlr_length + length_coding_size(trlr_length);
    } else {
        throw deserialization_error("Unsupported SecuredMessage protocol version");
    }
    return length;
}

size_t deserialize(InputArchive& ar, SecuredMessageV3& message)
{
    size_t available = ar.get_available();
    if (available<1){
        throw security::deserialization_error("Unsupported SecuredMessage protocol version");
    }
    vanetza::ByteBuffer temp(available);
    ar.load_binary(temp.data(), temp.size());
    message = SecuredMessageV3(temp);
    return message.get_size();
}


size_t deserialize(InputArchive& ar, SecuredMessageVariant& message)
{
    class canonical_visitor : public boost::static_visitor<size_t>
    {
        public:
            canonical_visitor(InputArchive& ir): ir_(ir){}
            size_t operator()(SecuredMessageV2& message) const
            {
                return deserialize(ir_, message);
            }

            size_t operator()(SecuredMessageV3& message) const
            {
                return deserialize(ir_, message);
            }

            InputArchive& ir_;
    };
    canonical_visitor visitor(ar);
    return boost::apply_visitor(visitor, message);
}



ByteBuffer convert_for_signing(const SecuredMessage& message, const std::list<TrailerField>& trailer_fields)
{
    ByteBuffer buf;
    byte_buffer_sink sink(buf);

    boost::iostreams::stream_buffer<byte_buffer_sink> stream(sink);
    OutputArchive ar(stream);

    const uint8_t protocol_version = message.protocol_version();
    ar << protocol_version;
    serialize(ar, message.header_fields);
    serialize(ar, message.payload);

    // Encode the total length, all trailer fields before the signature and the type of the signature
    // (see TS 103 097 v1.2.1, section 5.6)
    serialize_length(ar, get_size(trailer_fields));
    for (auto& elem : trailer_fields) {
        TrailerFieldType type = get_type(elem);
        if (type == TrailerFieldType::Signature) {
            serialize(ar, type);
            break; // exclude fields after signature
        } else {
            serialize(ar, elem);
        }
    }

    stream.close();
    return buf;
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


SecuredMessageV3::SecuredMessageV3(){
    vanetza::ByteBuffer white_message_buffer{
          0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x00, 0x00  
, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  
, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  
, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    this->message.decode(white_message_buffer);
}

SecuredMessageV3::~SecuredMessageV3(){
}

SecuredMessageV3::SecuredMessageV3(vanetza::ByteBuffer secured_message){
    bool encoded = this->message.decode(secured_message);
    if (!encoded){
        throw security::deserialization_error("Message not correct!");
    }
}

SecuredMessageV3::SecuredMessageV3(const SecuredMessageV3& message){
    this->message.decode(message.serialize());
}

vanetza::ByteBuffer SecuredMessageV3::serialize() const {
    return this->message.encode();
}

size_t SecuredMessageV3::get_size() const {
    return this->message.size();
}

std::shared_ptr<Time64> SecuredMessageV3::get_generation_time() const{
    std::shared_ptr<Time64> to_return;

    if(this->is_signed_message() && this->message->content->choice.signedData->tbsData->headerInfo.generationTime){
        Time64_t* time = this->message->content->choice.signedData->tbsData->headerInfo.generationTime;
        to_return.reset(new Time64(0));
        asn_INTEGER2ulong(time, to_return.get());
    }
    return to_return;
}

Psid_t SecuredMessageV3::get_psid() const{
    if(this->is_signed_message()){
        Psid_t psid = this->message->content->choice.signedData->tbsData->headerInfo.psid;
        return psid;
    }
    return 0;
}

std::shared_ptr<ThreeDLocation> SecuredMessageV3::get_generation_location() const{
    std::shared_ptr<ThreeDLocation> three_d_location;
    if(this->is_signed_message() && this->message->content->choice.signedData->tbsData->headerInfo.generationLocation){
        ThreeDLocation_t* location = this->message->content->choice.signedData->tbsData->headerInfo.generationLocation;
        three_d_location.reset(new ThreeDLocation(vanetza::units::GeoAngle(location->latitude*boost::units::degree::degrees),
            vanetza::units::GeoAngle(location->longitude*boost::units::degree::degrees)));
    }
    return three_d_location;
}


bool SecuredMessageV3::is_signed_message() const {
    if (this->message->content->present == Ieee1609Dot2Content_PR_signedData){
        return true;
    }
    return false;
}

SignerInfoV3 SecuredMessageV3::get_signer_info() const{
    SignerInfoV3 to_return = std::nullptr_t();
    if (this->is_signed_message()){
        this->message->content->choice.signedData->signer;
        switch (this->message->content->choice.signedData->signer.present)
        {
        
        case SignerIdentifier_PR_digest:
            to_return = CertificateV3::HashedId8_asn_to_HashedId8(this->message->content->choice.signedData->signer.choice.digest);
            break;
        case SignerIdentifier_PR_certificate:
            SequenceOfCertificate_t certificates = this->message->content->choice.signedData->signer.choice.certificate;
            // if (certificates.list.size==1){
            //     Certificate_t* temp = reinterpret_cast<Certificate_t*>(certificates.list.array[0]);
            //     to_return = boost::recursive_wrapper<CertificateV3>(*temp);
            // }else 
            if (certificates.list.size > 0){
                std::list<CertificateV3> before_to_return = std::list<CertificateV3>();
                for (int i=0;i<certificates.list.count; i++){
                    Certificate_t* temp = reinterpret_cast<Certificate_t*>(certificates.list.array[i]);
                    vanetza::ByteBuffer temp_buffer = vanetza::asn1::encode_oer(asn_DEF_Certificate, temp);
                    before_to_return.push_back(CertificateV3(temp_buffer));
                }
                to_return = before_to_return;
            }
            break;
        }        
    }
    return to_return;
} // To be completed!

bool SecuredMessageV3::is_signer_digest() const{
    bool to_return = false;
    if (this->is_signed_message()){
        if (this->message->content->choice.signedData->signer.present == SignerIdentifier_PR_digest){
            to_return = true;
        }
    }
    return to_return;
}

std::list<HashedId3> SecuredMessageV3::get_inline_p2pcd_Request() const{
    std::list<HashedId3> to_return{};
    if (this->is_signed_message()){
        SequenceOfHashedId3_t * inlineP2pcdRequest = this->message->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest;
        if (inlineP2pcdRequest){
            for (int i=0; i<inlineP2pcdRequest->list.count; i++){
                HashedId3 new_elem = CertificateV3::HashedId3_asn_to_HashedId3(*inlineP2pcdRequest->list.array[i]);
                to_return.push_back(new_elem);
            }
        }
    }
    return to_return;
}// Test to be written

vanetza::security::Signature SecuredMessageV3::get_signature() const{
    vanetza::security::Signature to_return{};
    if (this->is_signed_message()){
        if (this->message->content->choice.signedData->signature.present == Signature_PR_ecdsaNistP256Signature){
            vanetza::security::EcdsaSignature signature;
            Signature_t ssignature = this->message->content->choice.signedData->signature;
            EcdsaP256Signature_t nsignature;
            bool assigned = false;
            switch (ssignature.present)
            {
            case Signature_PR_ecdsaNistP256Signature:
                nsignature = ssignature.choice.ecdsaNistP256Signature;
                assigned = true;
                break;
            case Signature_PR_ecdsaBrainpoolP256r1Signature:
                nsignature = ssignature.choice.ecdsaBrainpoolP256r1Signature;
                assigned = true;
                break;
            case Signature_PR_ecdsaBrainpoolP384r1Signature:
                //nsignature = ssignature.choice.ecdsaBrainpoolP384r1Signature;
                //assigned = true;
                break;
            default:
                break;
            }

            if (assigned){
                signature.s = CertificateV3::OCTET_STRING_to_ByteBuffer(nsignature.sSig);
                switch(nsignature.rSig.present){
                    case EccP256CurvePoint_PR_x_only:
                        signature.R = X_Coordinate_Only{
                            .x=CertificateV3::OCTET_STRING_to_ByteBuffer(nsignature.rSig.choice.x_only)
                        };
                        break;
                    case EccP256CurvePoint_PR_fill:
                        break;
                    case EccP256CurvePoint_PR_compressed_y_0:
                        signature.R = Compressed_Lsb_Y_0{
                            .x=CertificateV3::OCTET_STRING_to_ByteBuffer(nsignature.rSig.choice.compressed_y_0)
                        };
                        break;
                    case EccP256CurvePoint_PR_compressed_y_1:
                        signature.R = Compressed_Lsb_Y_1{
                            .x=CertificateV3::OCTET_STRING_to_ByteBuffer(nsignature.rSig.choice.compressed_y_1)
                        };
                        break;
                    case EccP256CurvePoint_PR_uncompressedP256:
                        signature.R = Uncompressed{
                            .x=CertificateV3::OCTET_STRING_to_ByteBuffer(nsignature.rSig.choice.uncompressedP256.x),
                            .y=CertificateV3::OCTET_STRING_to_ByteBuffer(nsignature.rSig.choice.uncompressedP256.y)
                        };
                        break;
                }
                to_return = signature;
            }
        }
    }
    return to_return;
} // Function to be tested!

vanetza::ByteBuffer SecuredMessageV3::get_payload() const{
    vanetza::ByteBuffer to_return;
    if (this->is_signed_message()){
        to_return = CertificateV3::OCTET_STRING_to_ByteBuffer(
            this->message->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData
        );
    }
    return to_return;
}


vanetza::ByteBuffer SecuredMessageV3::convert_for_signing() const{
    vanetza::ByteBuffer to_return;
    if (this->is_signed_message()){
        try{
            to_return = vanetza::asn1::encode_oer(asn_DEF_ToBeSignedData, this->message->content->choice.signedData->tbsData);
        }catch(std::runtime_error& er){
            // std::cout << er.what();
        }
    }
    return to_return;
}

void SecuredMessageV3::set_generation_time(Time64 time){
    asn_uint642INTEGER(
        (this->message->content->choice.signedData->tbsData->headerInfo.generationTime),
        time
    );
}

void SecuredMessageV3::set_psid(Psid_t psid){
    this->message->content->choice.signedData->tbsData->headerInfo.psid = psid;
}

void SecuredMessageV3::set_certificate_digest(HashedId8 digest){
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SignerIdentifier, &(this->message->content->choice.signedData->signer));
    this->message->content->choice.signedData->signer.present = SignerIdentifier_PR_digest;
    OCTET_STRING_fromBuf(
            &(this->message->content->choice.signedData->signer.choice.digest),
            reinterpret_cast<const char *>(digest.data()),
            digest.size()
        );
}


void SecuredMessageV3::set_inline_p2pcd_request(std::list<HashedId3> requests){
    ASN_STRUCT_FREE_CONTENTS_ONLY(
        asn_DEF_SequenceOfHashedId3,
        &(this->message->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest)
    );
    for (HashedId3 request : requests){
        HashedId3_t* temp = static_cast<HashedId3_t*>(vanetza::asn1::allocate(sizeof(HashedId3_t)));
        OCTET_STRING_fromBuf(
            temp,
            reinterpret_cast<const char *>(request.data()),
            request.size()
        );
        ASN_SEQUENCE_ADD(
            &(this->message->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest->list),
            temp
        );
    }
} // TO BE TESTED


void SecuredMessageV3::set_generation_location(ThreeDLocation location){
    ThreeDLocation_t* new_location = static_cast<ThreeDLocation_t*>(vanetza::asn1::allocate(sizeof(ThreeDLocation_t)));
    new_location->latitude = location.latitude.value();
    new_location->longitude = location.longitude.value();
    new_location->elevation = 0;
    if (location.elevation != location.unknown_elevation){
        //new_location.elevation = ((uint16_t)location.elevation.data()[0] << 8) | location.elevation.data()[1];
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(
        asn_DEF_ThreeDLocation, 
        &(this->message->content->choice.signedData->tbsData->headerInfo.generationLocation)
    );
    this->message->content->choice.signedData->tbsData->headerInfo.generationLocation = new_location;
} // TO BE TESTED


void SecuredMessageV3::set_payload(const vanetza::ByteBuffer& payload){
    convert_bytebuffer_to_octet_string(
        &(this->message->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData),
        payload
    );
}

void SecuredMessageV3::set_signature(const Signature& signature){
    struct ecc_point_visitor : public boost::static_visitor<EccP256CurvePoint_t> {
            EccP256CurvePoint_t operator()(const X_Coordinate_Only& x_only) const
            {
                EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
                to_return->present = EccP256CurvePoint_PR_x_only;
                convert_bytebuffer_to_octet_string(
                    &(to_return->choice.x_only),
                    x_only.x
                );
                return *to_return;
            }

            EccP256CurvePoint_t operator()(const Compressed_Lsb_Y_0& y0) const
            {
                EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
                to_return->present = EccP256CurvePoint_PR_compressed_y_0;
                convert_bytebuffer_to_octet_string(
                    &(to_return->choice.compressed_y_0),
                    y0.x
                );
                return *to_return;
            }

            EccP256CurvePoint_t operator()(const Compressed_Lsb_Y_1& y1) const
            {
                EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
                to_return->present = EccP256CurvePoint_PR_compressed_y_1;
                convert_bytebuffer_to_octet_string(
                    &(to_return->choice.compressed_y_1),
                    y1.x
                );
                return *to_return;
            }

            EccP256CurvePoint_t operator()(const Uncompressed& unc) const
            {
                EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
                to_return->present = EccP256CurvePoint_PR_uncompressedP256;
                convert_bytebuffer_to_octet_string(
                    &(to_return->choice.uncompressedP256.x),
                    unc.x
                );
                convert_bytebuffer_to_octet_string(
                    &(to_return->choice.uncompressedP256.y),
                    unc.y
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
                convert_bytebuffer_to_octet_string(
                    &(final_signature->choice.ecdsaNistP256Signature.sSig),
                    signature.s
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
                Signature temp = signature.get();
                final_signature = boost::apply_visitor(signature_visitor(), temp);
                return final_signature;
            }
        };
    this->message->content->choice.signedData->signature = boost::apply_visitor(signature_visitor(), signature);
}

void SecuredMessageV3::set_signer_info(const SignerInfoV3& signer_info){
    struct signer_info_visitor : public boost::static_visitor<SignerIdentifier_t*>
        {
            SignerIdentifier_t* operator()(const std::nullptr_t& pnullptr ) const
            {
                return nullptr;
            }

            SignerIdentifier_t* operator()(const HashedId8& hashedId8) const
            {
                SignerIdentifier_t* signer = static_cast<SignerIdentifier_t*>(vanetza::asn1::allocate(sizeof(SignerIdentifier_t)));
                signer->present = SignerIdentifier_PR_digest;
                OCTET_STRING_fromBuf(
                    &(signer->choice.digest),
                    reinterpret_cast<const char *>(hashedId8.data()),
                    hashedId8.size()
                );
                return signer;
            }

            SignerIdentifier_t* operator()(const boost::recursive_wrapper<CertificateV3>& certificate) const
            {
                SignerIdentifier_t* signer = static_cast<SignerIdentifier_t*>(vanetza::asn1::allocate(sizeof(SignerIdentifier_t)));
                signer->present = SignerIdentifier_PR_certificate;
                Certificate_t* certi = static_cast<Certificate_t*>(vanetza::asn1::allocate(sizeof(Certificate_t)));
                certificate.get().as_plain_certificate(certi);
                ASN_SEQUENCE_ADD(&(signer->choice.certificate), certi);
                return signer;
            }

            SignerIdentifier_t* operator()(const std::list<CertificateV3>& certificates) const
            {
                SignerIdentifier_t* signer = static_cast<SignerIdentifier_t*>(vanetza::asn1::allocate(sizeof(SignerIdentifier_t)));
                signer->present = SignerIdentifier_PR_certificate;
                for (auto const& cert : certificates){
                    Certificate_t* certi = static_cast<Certificate_t*>(vanetza::asn1::allocate(sizeof(Certificate_t)));
                    cert.as_plain_certificate(certi);
                    ASN_SEQUENCE_ADD(&(signer->choice.certificate), certi);
                }
                return signer;
            }

            SignerIdentifier_t* operator()(const CertificateDigestWithOtherAlgorithm& certificate) const
            {
                SignerIdentifier_t* signer = static_cast<SignerIdentifier_t*>(vanetza::asn1::allocate(sizeof(SignerIdentifier_t)));
                signer->present = SignerIdentifier_PR_digest;
                OCTET_STRING_fromBuf(
                    &(signer->choice.digest),
                    reinterpret_cast<const char *>(certificate.digest.data()),
                    certificate.digest.size()
                );
                return signer;
            }
        };
    SignerIdentifier_t* temp = boost::apply_visitor(signer_info_visitor(), signer_info);
    if (temp){
        ASN_STRUCT_FREE_CONTENTS_ONLY(
            asn_DEF_SignerIdentifier,
            &(this->message->content->choice.signedData->signer)
        );
        this->message->content->choice.signedData->signer = *temp;
    }
}

} // namespace security
} // namespace vanetza
