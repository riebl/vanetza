#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/optional/optional.hpp>
#include <iosfwd>
#include <stdexcept>
#include <string>
#include <utility>

namespace vanetza
{
namespace pki
{

using HttpResponse = boost::beast::http::response<boost::beast::http::string_body>;

struct HttpException : public std::runtime_error
{
    using std::runtime_error::runtime_error;

    HttpException(const std::string& what, HttpResponse response) :
        std::runtime_error(what), m_response(std::move(response))
    {
    }

    // Server response associated with the failure, if any.
    const boost::optional<HttpResponse>& response() const { return m_response; }

private:
    boost::optional<HttpResponse> m_response;
};

std::ostream& operator<<(std::ostream& os, const HttpException& e);

struct HttpQuery
{
    static HttpQuery from_url(const std::string&);

    bool secure = false;
    std::string host;
    std::string service;
    std::string path;

    const std::string& which_service() const;
};

/**
 * \brief Resolve a (possibly relative) URL reference against a base URL per RFC 3986 §5.
 *
 * An empty reference yields the base unchanged. A reference carrying its own scheme
 * (e.g. "https://...") is absolute and returned as-is. Otherwise it is resolved against
 * the base: "//authority/..." replaces the authority, a leading-slash path replaces the
 * base path, and any other path is merged onto the base's directory.
 * \throws HttpException if the base URL cannot be parsed
 */
std::string resolve_url(const std::string& base, const std::string& reference);

HttpResponse http_get(const HttpQuery& query);
HttpResponse http_post(const HttpQuery& query, const std::string& content_type, const ByteBuffer& body);

} // namespace pki
} // namespace vanetza
