#include "http.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <regex>

namespace vanetza
{
namespace pki
{

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = boost::asio::ssl;

HttpQuery HttpQuery::from_url(const std::string& url)
{
    std::regex url_regex { "^(https?)://([^:/]+)(?::([[:digit:]]+))?(/?|/.*)$" };
    std::smatch match;
    if (std::regex_match(url, match, url_regex) && match.size() == 5) {
        HttpQuery query;
        query.secure = (match[1] == "https");
        query.host = match[2];
        query.path = match[4];
        if (match[3].matched) {
            query.service = match[3];
        } else {
            query.service = match[1];
        }
        return query;
    } else {
        throw HttpException("URL is not acceptable");
    }
}

const std::string& HttpQuery::which_service() const
{
    if (service.empty()) {
        static const std::string http_service = "http";
        static const std::string https_service = "https";
        return secure ? https_service : http_service;
    } else {
        return service;
    }
}

static bool should_follow(int status)
{
    switch (status) {
        case 301:
        case 302:
        case 303:
        case 307:
        case 308:
            return true;
        default:
            return false;
    }
}

template<typename T>
HttpResponse query_http(const HttpQuery& query, const beast::http::request<T>& request, asio::io_context& io,
    ssl::context& ssl)
{
    asio::ip::tcp::resolver resolver(io);
    auto resolved = resolver.resolve(query.host, query.which_service());

    HttpResponse response;
    beast::flat_buffer buffer;

    if (query.secure) {
        ssl::stream<asio::ip::tcp::socket> stream(io, ssl);
        SSL_set_tlsext_host_name(stream.native_handle(), query.host.c_str());

        asio::connect(stream.lowest_layer(), resolved);
        stream.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
        stream.handshake(ssl::stream_base::client);

        beast::http::write(stream, request);
        beast::http::read(stream, buffer, response);
        beast::error_code ec;
        if (stream.shutdown(ec)) {
            // could log error in verbose mode
        }
    } else {
        asio::ip::tcp::socket socket(io);
        asio::connect(socket, resolved);
        beast::http::write(socket, request);
        beast::http::read(socket, buffer, response);
    }

    return response;
}

template<typename T>
HttpResponse query_http_redirections(HttpQuery query, const beast::http::request<T>& request, asio::io_context& io,
    ssl::context& ssl)
{
    constexpr unsigned max_hops = 5;
    for (unsigned hop = 0; hop < max_hops; ++hop) {
        auto resp = query_http(query, request, io, ssl);
        if (should_follow(resp.result_int())) {
            std::string location { resp[beast::http::field::location] };
            query = HttpQuery::from_url(location);
        } else {
            return resp;
        }
    }

    throw HttpException("too many redirects");
}

template<typename T> HttpResponse query_http(const HttpQuery& query, const beast::http::request<T>& request)
{
    asio::io_context io;

    ssl::context ssl(ssl::context::tlsv13_client);
    ssl.set_default_verify_paths();
    ssl.set_verify_mode(ssl::context::verify_peer);
    ssl.set_verify_callback(ssl::host_name_verification(query.host));

    auto resp = query_http(query, request, io, ssl);
    if (should_follow(resp.result_int())) {
        std::string location { resp[beast::http::field::location] };
        auto redirection = HttpQuery::from_url(location);
        return query_http_redirections(std::move(redirection), request, io, ssl);
    } else {
        return resp;
    }
}

HttpResponse http_get(const HttpQuery& query)
{
    beast::http::request<beast::http::empty_body> request;
    request.method(beast::http::verb::get);
    request.target(query.path);
    request.set(beast::http::field::host, query.host);

    return query_http(query, request);
}

HttpResponse http_post(const HttpQuery& query, const std::string& content_type, const ByteBuffer& data)
{
    beast::http::request<beast::http::string_body> request;
    request.method(beast::http::verb::post);
    request.target(query.path);
    request.set(beast::http::field::host, query.host);
    request.set(beast::http::field::content_type, content_type);
    request.body().assign(data.begin(), data.end());
    request.prepare_payload();

    return query_http(query, request);
}

} // namespace pki
} // namespace vanetza
