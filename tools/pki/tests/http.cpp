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

TEST(ResolveUrl, empty_reference_keeps_base)
{
    EXPECT_EQ("https://aa.example.com/aa/0001", resolve_url("https://aa.example.com/aa/0001", ""));
}

TEST(ResolveUrl, absolute_reference_passes_through)
{
    EXPECT_EQ("http://other.com/x", resolve_url("https://aa.example.com/aa/0001", "http://other.com/x"));
    EXPECT_EQ("https://other.com", resolve_url("https://aa.example.com/aa/0001", "https://other.com"));
}

TEST(ResolveUrl, absolute_path_replaces_path)
{
    EXPECT_EQ("https://aa.example.com/foo", resolve_url("https://aa.example.com/aa/0001", "/foo"));
    EXPECT_EQ("https://aa.example.com/", resolve_url("https://aa.example.com/aa/0001", "/"));
}

TEST(ResolveUrl, absolute_path_keeps_authority_with_port)
{
    EXPECT_EQ("https://aa.example.com:8443/foo", resolve_url("https://aa.example.com:8443/aa/0001", "/foo"));
}

TEST(ResolveUrl, relative_path_merges_onto_base_directory)
{
    EXPECT_EQ("https://aa.example.com/aa/foo", resolve_url("https://aa.example.com/aa/0001", "foo"));
    // base without a path is treated as having a root directory
    EXPECT_EQ("https://aa.example.com/foo", resolve_url("https://aa.example.com", "foo"));
    // a trailing slash on the base keeps the last segment
    EXPECT_EQ("https://aa.example.com/aa/0001/foo", resolve_url("https://aa.example.com/aa/0001/", "foo"));
}

TEST(ResolveUrl, network_path_replaces_authority_keeps_scheme)
{
    EXPECT_EQ("https://other.com/z", resolve_url("https://aa.example.com/aa/0001", "//other.com/z"));
    EXPECT_EQ("http://other.com/z", resolve_url("http://aa.example.com/aa/0001", "//other.com/z"));
}

TEST(ResolveUrl, base_query_and_fragment_are_dropped)
{
    EXPECT_EQ("https://aa.example.com/foo", resolve_url("https://aa.example.com/aa/0001?x=1#frag", "/foo"));
}

TEST(ResolveUrl, unparseable_base_throws)
{
    EXPECT_ANY_THROW(resolve_url("not-a-url", "/foo"));
}
