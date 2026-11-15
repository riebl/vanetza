#pragma once
#include <gtest/gtest.h>
#include <algorithm>
#include <string>

namespace vanetza
{
namespace security
{

// test names consist of alphanumerics only, e.g. implementation Crypto++ is named CryptoPP
inline std::string implementation_test_name(const ::testing::TestParamInfo<std::string>& info)
{
    std::string name = info.param;
    std::replace(name.begin(), name.end(), '+', 'P');
    return name;
}

} // namespace security
} // namespace vanetza
