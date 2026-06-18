#include "http.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <chrono>
#include <functional>
#include <ostream>
#include <regex>

namespace vanetza
{
namespace pki
{

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = boost::asio::ssl;

std::ostream& operator<<(std::ostream& os, const HttpException& e)
{
    os << e.what();
    if (const auto& response = e.response()) {
        os << " (HTTP " << response->result_int();
        if (!response->body().empty()) {
            os << ": " << response->body();
        }
        os << ")";
    }
    return os;
}

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

std::string resolve_url(const std::string& base, const std::string& reference)
{
    if (reference.empty()) {
        return base;
    }
    // A reference with its own scheme is already absolute (RFC 3986 §5.2.2).
    static const std::regex scheme_re { "^[a-zA-Z][a-zA-Z0-9+.-]*://" };
    if (std::regex_search(reference, scheme_re)) {
        return reference;
    }

    // Split the base into scheme, authority and path (RFC 3986 §3); drop any query/fragment.
    static const std::regex base_re { "^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)(/[^?#]*)?.*$" };
    std::smatch m;
    if (!std::regex_match(base, m, base_re)) {
        throw HttpException("base URL is not acceptable");
    }
    const std::string scheme = m[1];
    const std::string origin = scheme + "://" + std::string(m[2]); // scheme + authority
    const std::string base_path = m[3].matched ? std::string(m[3]) : "/";

    if (reference.compare(0, 2, "//") == 0) {
        // network-path reference: keep the base scheme, replace authority and path
        return scheme + ":" + reference;
    } else if (reference.front() == '/') {
        // absolute-path reference: replace the whole path
        return origin + reference;
    } else {
        // relative-path reference: merge onto the base's directory
        const std::string dir = base_path.substr(0, base_path.find_last_of('/') + 1);
        return origin + dir + reference;
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

namespace
{

// resolve and connect lifecycle of one address family taking part in a Happy Eyeballs race
class Family
{
public:
    explicit Family(asio::io_context& ctx) : m_socket(ctx) {}

    bool resolved() const { return static_cast<bool>(m_addresses); }
    bool connected() const { return m_error && !*m_error; }
    bool failed() const { return m_error && *m_error; }
    boost::system::error_code error() const { return m_error.value_or(boost::system::error_code {}); }

    void resolve(asio::ip::tcp::resolver& resolver, const asio::ip::tcp& protocol,
        const std::string& host, const std::string& service, const std::function<void()>& notify)
    {
        resolver.async_resolve(protocol, host, service,
            [this, notify](boost::system::error_code ec, asio::ip::tcp::resolver::results_type results) {
                if (ec) {
                    m_error = ec;
                } else {
                    m_addresses = results;
                }
                notify();
            });
    }

    void connect(const std::function<void()>& notify)
    {
        if (resolved() && !m_connecting && !m_error) {
            m_connecting = true;
            asio::async_connect(m_socket, *m_addresses,
                [this, notify](boost::system::error_code ec, const asio::ip::tcp::endpoint&) {
                    m_connecting = false;
                    m_error = ec;
                    notify();
                });
        }
    }

    // hand the connected socket over to another io_context
    asio::ip::tcp::socket release(asio::io_context& io)
    {
        return asio::ip::tcp::socket { io, m_socket.local_endpoint().protocol(), m_socket.release() };
    }

private:
    asio::ip::tcp::socket m_socket;
    boost::optional<asio::ip::tcp::resolver::results_type> m_addresses;
    boost::optional<boost::system::error_code> m_error;
    bool m_connecting = false; // a connect attempt is in flight
};

// Happy Eyeballs (RFC 8305): race AAAA/A lookups and per-family connect attempts, preferring IPv6
class HappyEyeballsRace
{
public:
    // winning socket is adopted by the caller's io_context
    static asio::ip::tcp::socket connect(asio::io_context& io, const std::string& host,
        const std::string& service, std::chrono::milliseconds deadline)
    {
        HappyEyeballsRace race;
        return race.run(host, service, deadline).release(io);
    }

private:
    // run the race and return the winning family, throw when nobody wins
    Family& run(const std::string& host, const std::string& service, std::chrono::milliseconds deadline)
    {
        timeout.expires_after(deadline);
        timeout.async_wait([this](boost::system::error_code ec) {
            if (!ec) {
                race.stop();
            }
        });
        v6.resolve(resolver, asio::ip::tcp::v6(), host, service, [this]() { on_v6_resolve_done(); });
        v4.resolve(resolver, asio::ip::tcp::v4(), host, service, [this]() { on_v4_resolve_done(); });
        race.run();

        if (v6.connected() || v4.connected()) {
            return v6.connected() ? v6 : v4;
        } else if (!v6.failed() || !v4.failed()) {
            throw HttpException("connect timed out");
        } else if (v6.resolved() || v4.resolved()) {
            throw HttpException("connect failed: " + (v6.resolved() ? v6.error() : v4.error()).message());
        } else {
            throw HttpException("resolve failed: " + (v6.error() ? v6.error() : v4.error()).message());
        }
    }

    void on_v6_resolve_done()
    {
        if (v6.resolved()) {
            v6.connect([this]() { on_v6_connect_done(); });
            open_v4_gate(stagger_delay); // IPv4 may compete once the attempt delay elapsed
        } else {
            open_v4_gate(std::chrono::milliseconds::zero()); // no AAAA answer, IPv4 goes at once
        }
        settle();
    }

    void on_v4_resolve_done()
    {
        if (is_v4_gate_open()) {
            v4.connect([this]() { settle(); });
        } else if (v4.resolved() && !v6.resolved()) {
            open_v4_gate(resolution_delay); // pending AAAA answer gets a short head start
        }
        settle();
    }

    void on_v6_connect_done()
    {
        if (v6.failed()) {
            open_v4_gate(std::chrono::milliseconds::zero()); // IPv6 lost, IPv4 takes over
        }
        settle();
    }

    void open_v4_gate(std::chrono::milliseconds delay)
    {
        v4_gate.expires_after(delay);
        v4_gate.async_wait([this](boost::system::error_code ec) {
            if (!ec) {
                v4.connect([this]() { settle(); });
            }
        });
    }

    bool is_v4_gate_open() const
    {
        return v4_gate.expiry() <= asio::steady_timer::clock_type::now();
    }

    void settle()
    {
        // stop the race once a connection is established or both families have failed
        if (v6.connected() || v4.connected() || (v6.failed() && v4.failed())) {
            race.stop();
        }
    }

    static constexpr std::chrono::milliseconds resolution_delay { 50 }; // RFC 8305 head start for the AAAA answer
    static constexpr std::chrono::milliseconds stagger_delay { 200 }; // connection attempt delay

    asio::io_context race;
    asio::ip::tcp::resolver resolver { race };
    Family v6 { race };
    Family v4 { race };
    asio::steady_timer v4_gate { race, asio::steady_timer::time_point::max() }; // gate starts closed
    asio::steady_timer timeout { race };
};

} // namespace

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
    constexpr std::chrono::seconds connect_deadline { 10 };
    HttpResponse response;
    beast::flat_buffer buffer;
    asio::ip::tcp::socket socket = HappyEyeballsRace::connect(io, query.host, query.which_service(), connect_deadline);

    if (query.secure) {
        ssl::stream<asio::ip::tcp::socket> stream(std::move(socket), ssl);
        SSL_set_tlsext_host_name(stream.native_handle(), query.host.c_str());

        stream.lowest_layer().set_option(asio::ip::tcp::no_delay(true));
        stream.handshake(ssl::stream_base::client);

        beast::http::write(stream, request);
        beast::http::read(stream, buffer, response);
        beast::error_code ec;
        if (stream.shutdown(ec)) {
            // could log error in verbose mode
        }
    } else {
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
