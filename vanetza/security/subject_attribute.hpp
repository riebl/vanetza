#ifndef SUBJECT_ATTRIBUTE_HPP_IRZLEB7C
#define SUBJECT_ATTRIBUTE_HPP_IRZLEB7C

#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/int_x.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/variant/variant.hpp>
#include <list>

namespace vanetza
{
namespace security
{

struct SubjectAssurance
{
    SubjectAssurance(uint8_t _raw = 0) : raw(_raw) {}

    static const uint8_t assurance_mask = 0xE0;
    static const uint8_t confidence_mask = 0x03;

    uint8_t raw;
};

struct ItsAidSsp
{
    IntX its_aid;
    ByteBuffer service_specific_permissions;
};

enum class SubjectAttributeType : uint8_t {
    Verification_Key = 0,       //VerificationKey
    Encryption_Key = 1,         //EncryptionKey
    Assurance_Level = 2,        //SubjectAssurance
    Reconstruction_Value = 3,   //EccPoint
    Its_Aid_List = 32,          //std::list<IntX>
    Its_Aid_Ssp_List = 33,      //std::list<ItsAidSsp>
};

struct VerificationKey
{
    PublicKey key;
};

struct EncryptionKey
{
    PublicKey key;
};

using SubjectAttribute =
    boost::variant<
        VerificationKey,
        EncryptionKey,
        SubjectAssurance,
        EccPoint,
        std::list<IntX>,
        std::list<ItsAidSsp>
    >;

/**
 * Determines SubjectAttributeType to a given SubjectAttribute
 * \param SubjectAttribute
 */
SubjectAttributeType get_type(const SubjectAttribute&);

/**
 * Calculates size of an object
 * \param Object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const SubjectAttribute&);
size_t get_size(const SubjectAssurance&);
size_t get_size(const ItsAidSsp&);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, SubjectAttribute&);
size_t deserialize(InputArchive&, ItsAidSsp&);

/**
 * Serializes an object into a binary archive
 * \param object to serialize
 * \param achive to serialize in,
 */
void serialize(OutputArchive&, const SubjectAttribute&);
void serialize(OutputArchive&, const ItsAidSsp&);

} // namespace security
} // namespace vanetza

#endif /* SUBJECT_ATTRIBUTE_HPP_IRZLEB7C */
