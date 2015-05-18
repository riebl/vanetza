#ifndef SUBJECT_ATTRIBUTE_HPP_IRZLEB7C
#define SUBJECT_ATTRIBUTE_HPP_IRZLEB7C

#include <vanetza/security/int_x.hpp>
#include <vanetza/security/public_key.hpp>
#include <list>

namespace vanetza
{
namespace security
{

using SubjectAssurance = uint8_t;

struct ItsAidSsp
{
    IntX its_aid;
    ByteBuffer service_specific_permissions;
};

struct ItsAidPriority
{
    IntX its_aid;
    uint8_t max_priority;
};

struct ItsAidPrioritySsp
{
    IntX its_aid;
    uint8_t max_priority;
    ByteBuffer service_specific_permissions;
};

enum class SubjectAttributeType : uint8_t {
    Verification_Key = 0,       //VerificationKey
    Encryption_Key = 1,         //EncryptionKey
    Assurance_Level = 2,        //SubjectAssurance
    Reconstruction_Value = 3,   //EccPoint
    Its_Aid_List = 32,          //std::list<IntX>
    Its_Aid_Ssp_List = 33,      //std::list<ItsAidSsp>
    Priority_Its_Aid_List = 34, //std::list<ItsAidPriority>
    Priority_Ssp_List = 35      //std::list<ItsAidPrioritySsp>
};

struct VerificationKey
{
    PublicKey key;
};
struct EncryptionKey
{
    PublicKey key;
};

typedef boost::variant<VerificationKey, EncryptionKey, SubjectAssurance, EccPoint,
    std::list<ItsAidSsp>, std::list<ItsAidPriority>, std::list<ItsAidPrioritySsp>, std::list<IntX>> SubjectAttribute;
//TODO: EccPoint not used at the moment

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
size_t get_size(const std::list<IntX>&);
size_t get_size(const SubjectAssurance&);
size_t get_size(const std::list<ItsAidSsp>&);
size_t get_size(const std::list<ItsAidPriority>&);
size_t get_size(const std::list<ItsAidPrioritySsp>&);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, SubjectAttribute&);
size_t deserialize(InputArchive&, std::list<IntX>&);
size_t deserialize(InputArchive&, std::list<ItsAidSsp>&);
size_t deserialize(InputArchive&, std::list<ItsAidPriority>&);
size_t deserialize(InputArchive&, std::list<ItsAidPrioritySsp>&);

/**
 * Serializes an object into a binary archive
 * \param object to serialize
 * \param achive to serialize in,
 */
void serialize(OutputArchive&, const SubjectAttribute&);
void serialize(OutputArchive&, const std::list<IntX>&);
void serialize(OutputArchive&, const std::list<ItsAidSsp>&);
void serialize(OutputArchive&, const std::list<ItsAidPriority>&);
void serialize(OutputArchive&, const std::list<ItsAidPrioritySsp>&);

} // namespace security
} // namespace vanetza

#endif /* SUBJECT_ATTRIBUTE_HPP_IRZLEB7C */
