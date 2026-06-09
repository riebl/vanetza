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

HttpResponse http_get(const HttpQuery& query);
HttpResponse http_post(const HttpQuery& query, const std::string& content_type, const ByteBuffer& body);

} // namespace pki
} // namespace vanetza
