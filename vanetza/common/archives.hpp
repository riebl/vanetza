#ifndef ARCHIVES_HPP_TLVURDQK
#define ARCHIVES_HPP_TLVURDQK

#include <vanetza/common/byte_order.hpp>
#include <exception>
#include <istream>
#include <ostream>
#include <streambuf>

namespace vanetza
{

/**
 * This is a drop-in replacement for boost::archive::binary_iarchive
 */
class InputArchive
{
public:
    using InputStream = std::basic_istream<char>;
    using StreamBuffer = std::basic_streambuf<char>;
    class Exception : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    InputArchive(InputStream& is);
    InputArchive(StreamBuffer& buf);

    template<typename T>
    InputArchive& operator>>(T& t)
    {
        static_assert(std::is_integral<T>::value == true, "only integral types are supported");
        char* ptr = reinterpret_cast<char*>(&t);
        load_binary(ptr, sizeof(T));
        return *this;
    }

    void load_binary(unsigned char* data, std::size_t len);
    void load_binary(char* data, std::size_t len);

private:
    StreamBuffer* m_stream_buffer;
};

/**
 * This is a drop-in replacement for boost::archive::binary_oarchive
 */
class OutputArchive
{
public:
    using OutputStream = std::basic_ostream<char>;
    using StreamBuffer = std::basic_streambuf<char>;
    class Exception : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    OutputArchive(OutputStream& os);
    OutputArchive(StreamBuffer& buf);

    template<typename T>
    OutputArchive& operator<<(const T& t)
    {
        static_assert(std::is_integral<T>::value == true, "only integral types are supported");
        const char* ptr = reinterpret_cast<const char*>(&t);
        save_binary(ptr, sizeof(T));
        return *this;
    }

    void save_binary(const unsigned char* data, std::size_t len);
    void save_binary(const char* data, std::size_t len);

private:
    StreamBuffer* m_stream_buffer;
};

} // namespace vanetza

#endif /* ARCHIVES_HPP_TLVURDQK */

