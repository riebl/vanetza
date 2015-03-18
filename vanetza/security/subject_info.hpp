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

void serialize(OutputArchive&, const SubjectInfo&);
size_t deserialize(InputArchive&, SubjectInfo&);
size_t get_size(const SubjectInfo&);

} // namespace security
} // namespace vanetza

#endif /* SUBJECT_INFO_HPP_WCKSWSKY */

