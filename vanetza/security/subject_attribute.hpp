#ifndef SUBJECT_ATTRIBUTE_HPP_IRZLEB7C
#define SUBJECT_ATTRIBUTE_HPP_IRZLEB7C

#include <vanetza/security/int_x.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>
#include <list>

namespace vanetza
{
namespace security
{

/// SubjectAssurance specified in TS 103 097 v1.2.1 in section 6.6 and 7.4.1
struct SubjectAssurance
{
    SubjectAssurance(uint8_t _raw = 0) : raw(_raw) {}

    static constexpr uint8_t assurance_mask = 0xE0;
    static constexpr uint8_t confidence_mask = 0x03;

    uint8_t raw;

    uint8_t assurance() const
    {
        return (raw & assurance_mask) >> 5;
    }

    uint8_t confidence() const
    {
        return raw & confidence_mask;
    }
};

/// ItsAidSsp specified in TS 103 097 v1.2.1, section 6.9
struct ItsAidSsp
{
    IntX its_aid;
    ByteBuffer service_specific_permissions;
};

/// SubjectAttributeType specified in TS 103 097 v1.2.1, section 6.5
enum class SubjectAttributeType : uint8_t {
    Verification_Key = 0,       //VerificationKey
    Encryption_Key = 1,         //EncryptionKey
    Assurance_Level = 2,        //SubjectAssurance
    Reconstruction_Value = 3,   //EccPoint
    ITS_AID_List = 32,          //std::list<IntX>
    ITS_AID_SSP_List = 33,      //std::list<ItsAidSsp>
};

/// VerificationKey specified in TS 103 097 v1.2.1, section 6.4
struct VerificationKey
{
    PublicKey key;
};

/// EncryptionKey specified in TS 103 097 v1.2.1, section 6.4
struct EncryptionKey
{
    PublicKey key;
};

/// SubjectAttribute specified in TS 103 097 v1.2.1, section 6.4
using SubjectAttribute = boost::variant<
    VerificationKey,
    EncryptionKey,
    SubjectAssurance,
    EccPoint,
    std::list<IntX>,
    std::list<ItsAidSsp>
>;

/**
 * \brief Determines SubjectAttributeType to a given SubjectAttribute
 * \param attribute
 * \return type
 */
SubjectAttributeType get_type(const SubjectAttribute&);

/**
 * \brief Calculates size of a SubjectAttribute
 * \param sub
 * \return number of octets needed to serialize the SubjectAttribute
 */
size_t get_size(const SubjectAttribute&);

/**
 * \brief Calculates size of a SubjectAssurance
 * \param sub
 * \return number of octets needed to serialize the SubjectAssurance
 */
size_t get_size(const SubjectAssurance&);

/**
 * \brief Calculates size of an ItsAidSsp
 * \param its_aid_ssp
 * \return number of octets needed to serialize the ItsAidSsp
 */
size_t get_size(const ItsAidSsp&);

/**
 * \brief Deserializes a SubjectAttribute from a binary archive
 * \param ar with a serialized SubjectAttribute at the beginning
 * \param sub to deserialize
 * \return size of the deserialized SubjectAttribute
 */
size_t deserialize(InputArchive&, SubjectAttribute&);

/**
 * \brief Deserializes an ItsAidSsp from a binary archive
 * \param ar with a serialized ItsAidSsp at the beginning
 * \param its_aid_ssp to deserialize
 * \return size of the deserialized ItsAidSsp
 */
size_t deserialize(InputArchive&, ItsAidSsp&);

/**
 * \brief Serializes a SubjectAttribute into a binary archive
 * \param ar to serialize in
 * \param sub to serialize
 */
void serialize(OutputArchive&, const SubjectAttribute&);

/**
 * \brief Serializes an ItsAidSsp into a binary archive
 * \param ar to serialize in
 * \param its_aid_ssp to serialize
 */
void serialize(OutputArchive&, const ItsAidSsp&);

namespace detail
{

template<SubjectAttributeType>
struct subject_attribute_type;

template<>
struct subject_attribute_type<SubjectAttributeType::Verification_Key>
{
    using type = VerificationKey;
};

template<>
struct subject_attribute_type<SubjectAttributeType::Encryption_Key>
{
    using type = EncryptionKey;
};

template<>
struct subject_attribute_type<SubjectAttributeType::Assurance_Level>
{
    using type = SubjectAssurance;
};

template<>
struct subject_attribute_type<SubjectAttributeType::Reconstruction_Value>
{
    using type = EccPoint;
};

template<>
struct subject_attribute_type<SubjectAttributeType::ITS_AID_List>
{
    using type = std::list<IntX>;
};

template<>
struct subject_attribute_type<SubjectAttributeType::ITS_AID_SSP_List>
{
    using type = std::list<ItsAidSsp>;
};

} // namespace detail

/**
 * \brief resolve type for matching SubjectAttributeType
 *
 * This is kind of the reverse function of get_type(const SubjectAttribute&)
 */
template<SubjectAttributeType T>
using subject_attribute_type = typename detail::subject_attribute_type<T>::type;

} // namespace security
} // namespace vanetza

#endif /* SUBJECT_ATTRIBUTE_HPP_IRZLEB7C */
