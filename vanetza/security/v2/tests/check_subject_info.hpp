#ifndef CHECK_SUBJECT_INFO_HPP_LCHGB2G3
#define CHECK_SUBJECT_INFO_HPP_LCHGB2G3

#include <gtest/gtest.h>
#include <vanetza/security/v2/subject_info.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

inline void check(const SubjectInfo& expected, const SubjectInfo& actual)
{
    EXPECT_EQ(expected.subject_type, actual.subject_type);
    EXPECT_EQ(expected.subject_name, actual.subject_name);
}

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* CHECK_SUBJECT_INFO_HPP_LCHGB2G3 */

