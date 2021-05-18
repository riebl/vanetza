#ifndef SECURED_MESSAGE_HPP_MO3HBSXG
#define SECURED_MESSAGE_HPP_MO3HBSXG

#include <vanetza/asn1/etsi_secured_data.hpp>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/payload.hpp>
#include <cstdint>
#include <list>

namespace vanetza
{
namespace security
{

/// SecuredMessage as specified in TS 103 097 v1.2.1, section 5.1
struct SecuredMessageV2
{
    std::list<HeaderField> header_fields;
    std::list<TrailerField> trailer_fields;
    Payload payload;

    uint8_t protocol_version() const { return 2; }

    /**
     * Fetch pointer to first matching header field
     * \param type HeaderField has to match given type
     * \return matching HeaderField or nullptr
     */
    HeaderField* header_field(HeaderFieldType);

    /**
     * Fetch read-only pointer to first machting header field
     * \param type requested header field type
     * \return matching header field or nullptr
     */
    const HeaderField* header_field(HeaderFieldType type) const;

    /**
     * Fetch pointer to first matching trailer field
     * \param type TrailerField has to match given type
     * \return matching TrailerField or nullptr
     */
    TrailerField* trailer_field(TrailerFieldType);

    /**
     * Fetch read-only pointer of first matching trailer field
     * \param type request trailer field type
     * \return matching trailer field or nullptr
     */
    const TrailerField* trailer_field(TrailerFieldType type) const;

    template<HeaderFieldType T>
    typename header_field_type<T>::type* header_field()
    {
        using field_type = typename header_field_type<T>::type;
        HeaderField* field = header_field(T);
        return boost::get<field_type>(field);
    }

    template<HeaderFieldType T>
    const typename header_field_type<T>::type* header_field() const
    {
        using field_type = typename header_field_type<T>::type;
        const HeaderField* field = header_field(T);
        return boost::get<field_type>(field);
    }

    template<TrailerFieldType T>
    typename trailer_field_type<T>::type* trailer_field()
    {
        using field_type = typename trailer_field_type<T>::type;
        TrailerField* field = trailer_field(T);
        return boost::get<field_type>(field);
    }

    template<TrailerFieldType T>
    const typename trailer_field_type<T>::type* trailer_field() const
    {
        using field_type = typename trailer_field_type<T>::type;
        const TrailerField* field = trailer_field(T);
        return boost::get<field_type>(field);
    }
};

class SecuredMessageV3{
    public:
         /**
         * \brief Constructor of SecuredMessage V1.3.1 (Creates a white message completely empty)
         */
        SecuredMessageV3();
        ~SecuredMessageV3();
        /**
         * \brief Constructor of SecuredMessage V1.3.1 (Deserializes the COER encoded Secured Message)
         */
        SecuredMessageV3(vanetza::ByteBuffer secured_message);
        /**
         * \brief Constructor of SecuredMessage V1.3.1 (Copy Constructor)
         */
        SecuredMessageV3(const SecuredMessageV3& message);
        /**
         * \brief Returns the version of the standard
         * \return integer version (3)
         */
        uint8_t protocol_version() const { return 3; }
        /**
         * \brief Returns the serialized version of the SecuredMessage V1.3.1 in COER format
         * \return Buffer with the serialized message
         */
        vanetza::ByteBuffer serialize() const;
        /**
         * \brief Returns the size of serialized version of the SecuredMessage V1.3.1 in COER format
         * \return size 
         */
        size_t get_size() const;
        /**
         * \brief Getter of the generation time of the SecuredMessage V1.3.1
         * \return Shared pointer to Time 
         */
        std::shared_ptr<Time64> get_generation_time() const;
        /**
         * \brief Returns the PSID (ITS-AID) (Getter)
         * \return Psid (ITS-AID) 
         */
        Psid_t get_psid() const;
        /**
         * \brief Getter for the generation location (ThreeDLocation)
         * \return Shared Pointer ThreeDLocation
         */
        std::shared_ptr<ThreeDLocation> get_generation_location() const; // Test to be written
        /**
         * \brief Returns if the message is Signed
         * \return boolean
         */
        bool is_signed_message() const;
        /**
         * \brief Returns the signer info
         * \return Signer info
         */
        SignerInfo get_signer_info() const;
        /**
         * \brief Returns if the message is Signed with a digest
         * \return boolean
         */
        bool is_signer_digest() const;

        /**
         * \brief Returns a list with the unknown certificates demanded
         * 
         * \return List of hashedId3 with all the unkown certificates. 
         * (if the field is not present the list is returned empty)
         */
        std::list<HashedId3> get_inline_p2pcd_Request() const;
        /**
         * \brief Getter of the signature
         * \return Signature
         */
        vanetza::security::Signature get_signature() const;
        /**
         * \brief Getter of the payload of the message
         * \return Bytebuffer of payload
         */
        vanetza::ByteBuffer get_payload() const;
        /**
         * \brief Getter of the part of the to be signed part of the message
         * \return ByteBuffer
         */
        vanetza::ByteBuffer convert_for_signing() const;
        /**
         * \brief Setter of the generation of the time
         * \param time Time of the generation of the message
         */
        void set_generation_time(Time64 time);
        /**
         * \brief Setter of ITS-AID Psid
         * \param psid App permissions
         */
        void set_psid(Psid_t psid);
        /**
         * \brief Setter of the digest of the signer certificate
         * \param digest digest
         */
        void set_certificate_digest(HashedId8 digest);
        /**
         * \brief Setter of the request of unknown certificates
         * \param requests List of requested certificates
         */
        void set_inline_p2pcd_request(std::list<HashedId3> requests);
        /**
         * \brief Setter of the Location of the message
         * \param location ThreeDLocation 
         */
        void set_generation_location(ThreeDLocation location);
        /**
         * \brief Setter of payload
         * \param payload Buffer with the payload
         */
        void set_payload(const vanetza::ByteBuffer& payload);
        /**
         * \brief Setter of the signature of the message
         * \param signature Signature
         */
        void set_signature(const Signature& signature);
        /**
         * \brief Setter of the signer info
         * \param signer_info Signer Info
         */
        void set_signer_info(const SignerInfo& signer_info);

    private:
        vanetza::asn1::EtsiTs103097Data message;

};


using SecuredMessageVariant = boost::variant<SecuredMessageV2, SecuredMessageV3>;
using SecuredMessage = SecuredMessageVariant;

enum class SecuredMessageVersion
{
    Two,
    Three
};

/**
 * \brief Calculates size of a SecuredMessage object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const SecuredMessageV2&);

/**
 * \brief Calculates size of a SecuredMessageV3 object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const SecuredMessageV3&);

/**
 * \brief Calculates size of a SecuredMessage object (The version doesn't matter)
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const SecuredMessageVariant&);


/**
 * \brief Serializes a SecuredMessage into a binary archive
 */
void serialize(OutputArchive& ar, const SecuredMessageV2& message);

/**
 * \brief Serializes a SecuredMessageV3 into a binary archive
 */
void serialize(OutputArchive& ar, const SecuredMessageV3& message);

/**
 * \brief Serializes a SecuredMessageV3 into a binary archive
 */
void serialize(OutputArchive& ar, const SecuredMessageVariant& message);


/**
 * \brief Deserializes a SecuredMessage from a binary archive
 * \return size of deserialized SecuredMessage
 */
size_t deserialize(InputArchive& ar, SecuredMessageV2& message);

/**
 * \brief Deserializes a SecuredMessageV3 from a binary archive
 * \return size of deserialized SecuredMessage
 */
size_t deserialize(InputArchive& ar, SecuredMessageV3& message);

/**
 * \brief Deserializes a SecuredMessageV3 from a binary archive
 * \return size of deserialized SecuredMessage
 */
size_t deserialize(InputArchive& ar, SecuredMessageVariant& message);


/**
 * \brief Create ByteBuffer equivalent of SecuredMessage suitable for signature creation
 *
 * ByteBuffer contains message's version, header_fields and payload.
 * Additionally, the length of trailer fields and the type of the signature is appended.
 *
 * \param message
 * \param trailer_fields only trailer fields up to signature will be included in byte buffer
 * \return serialized data fields relevant for signature creation
 */
ByteBuffer convert_for_signing(const SecuredMessageV2& message, const std::list<TrailerField>& trailer_fields);

ByteBuffer convert_to_payload(vanetza::DownPacket packet);

} // namespace security
} // namespace vanetza

#endif /* SECURED_MESSAGE_HPP_MO3HBSXG */
