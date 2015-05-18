#ifndef SUBJECT_INFO_HPP_WCKSWSKY
#define SUBJECT_INFO_HPP_WCKSWSKY

#include <vanetza/security/serialization.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

enum class SubjectType : uint8_t
{
    Enrollment_Credential = 0,
    Authorization_Ticket = 1,
    Authorization_Authority = 2,
    Enrollment_Atuhority = 3,
    Root_Ca = 4,
    Crl_Signer = 5
};

struct SubjectInfo
{
    SubjectType subject_type;
    ByteBuffer subject_name;
};


/**
 * Serializes a SubjectInfo into a binary archive
 * \param SubjectInfo to serialize
 * \param achive to serialize in
 */
void serialize(OutputArchive&, const SubjectInfo&);

/**
 * Deserializes a SubjectInfo from a binary archive
 * \param archive with a serialized SubjectInfo at the beginning
 * \param SubjectInfo to deserialize
 * \return size of the deserialized SubjectInfo
 */
size_t deserialize(InputArchive&, SubjectInfo&);

/**
 * Calculates size of a SubjectInfo
 * \param SubjectInfo
 * \return size_t containing the number of octets needed to serialize the SubjectInfo
 */
size_t get_size(const SubjectInfo&);

} // namespace security
} // namespace vanetza

#endif /* SUBJECT_INFO_HPP_WCKSWSKY */

