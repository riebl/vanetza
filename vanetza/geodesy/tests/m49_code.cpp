#include <vanetza/geodesy/m49_code.hpp>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <unordered_set>

using vanetza::geodesy::M49Code;

TEST(M49Code, value)
{
    M49Code code(276);
    EXPECT_EQ(276, code.value());
}

TEST(M49Code, equality)
{
    EXPECT_EQ(M49Code(276), M49Code(276));
    EXPECT_NE(M49Code(276), M49Code(250));
}

TEST(M49Code, std_hash)
{
    std::unordered_set<M49Code> codes;
    codes.insert(M49Code(276));
    codes.insert(M49Code(250));
    codes.insert(M49Code(276)); // duplicate
    EXPECT_EQ(2u, codes.size());
    EXPECT_EQ(1u, codes.count(M49Code(276)));
    EXPECT_EQ(1u, codes.count(M49Code(250)));
}

TEST(M49Code, std_less)
{
    std::map<M49Code, std::string> names;
    names[M49Code(276)] = "Germany";
    names[M49Code(250)] = "France";
    EXPECT_EQ("Germany", names.at(M49Code(276)));
    EXPECT_EQ("France", names.at(M49Code(250)));
}
