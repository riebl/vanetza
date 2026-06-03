#include "http.hpp"
#include <gtest/gtest.h>

using namespace vanetza::pki;

TEST(HttpQuery, from_url_http)
{
    HttpQuery result = HttpQuery::from_url("http://www.example.com");
    EXPECT_EQ("www.example.com", result.host);
    EXPECT_EQ("http", result.which_service());
    EXPECT_EQ("", result.path);
    EXPECT_FALSE(result.secure);
}

TEST(HttpQuery, from_url_http_with_port)
{
    HttpQuery result = HttpQuery::from_url("http://www.example.com:80");
    EXPECT_EQ("www.example.com", result.host);
    EXPECT_EQ("80", result.which_service());
    EXPECT_FALSE(result.secure);
}

TEST(HttpQuery, from_url_http_with_path)
{
    HttpQuery result = HttpQuery::from_url("http://www.example.com/foo/bar");
    EXPECT_EQ("www.example.com", result.host);
    EXPECT_EQ("/foo/bar", result.path);
}

TEST(HttpQuery, from_url_http_with_port_and_path)
{
    HttpQuery result = HttpQuery::from_url("http://www.example.com:80/foo/bar");
    EXPECT_EQ("www.example.com", result.host);
    EXPECT_EQ("/foo/bar", result.path);
    EXPECT_EQ("80", result.which_service());
}

TEST(HttpQuery, from_url_broken_prefix)
{
    EXPECT_ANY_THROW(HttpQuery::from_url("shttp://www.example.com"));
}

TEST(HttpQuery, from_url_https)
{
    HttpQuery result = HttpQuery::from_url("https://example.com/");
    EXPECT_EQ("example.com", result.host);
    EXPECT_EQ("/", result.path);
    EXPECT_EQ("https", result.which_service());
    EXPECT_TRUE(result.secure);
}

TEST(HttpQuery, from_url_https_with_port)
{
    HttpQuery result = HttpQuery::from_url("https://www.example.com:8080");
    EXPECT_EQ("www.example.com", result.host);
    EXPECT_EQ("", result.path);
    EXPECT_EQ("8080", result.which_service());
    EXPECT_TRUE(result.secure);
}
