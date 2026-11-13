#include <vanetza/security/pem.hpp>
#include <cctype>
#include <cstdint>

namespace vanetza
{
namespace security
{

namespace
{

const char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_value(char symbol)
{
    if (symbol >= 'A' && symbol <= 'Z') {
        return symbol - 'A';
    } else if (symbol >= 'a' && symbol <= 'z') {
        return symbol - 'a' + 26;
    } else if (symbol >= '0' && symbol <= '9') {
        return symbol - '0' + 52;
    } else if (symbol == '+') {
        return 62;
    } else if (symbol == '/') {
        return 63;
    } else {
        return -1;
    }
}

std::string encode_base64(const ByteBuffer& data)
{
    std::string text;
    text.reserve((data.size() + 2) / 3 * 4);
    for (std::size_t i = 0; i < data.size(); i += 3) {
        const std::size_t remaining = data.size() - i;
        std::uint32_t quantum = data[i] << 16;
        if (remaining > 1) {
            quantum |= data[i + 1] << 8;
        }
        if (remaining > 2) {
            quantum |= data[i + 2];
        }
        text.push_back(base64_alphabet[(quantum >> 18) & 0x3f]);
        text.push_back(base64_alphabet[(quantum >> 12) & 0x3f]);
        text.push_back(remaining > 1 ? base64_alphabet[(quantum >> 6) & 0x3f] : '=');
        text.push_back(remaining > 2 ? base64_alphabet[quantum & 0x3f] : '=');
    }
    return text;
}

boost::optional<ByteBuffer> decode_base64(const std::string& text)
{
    std::string symbols;
    for (char symbol : text) {
        if (!std::isspace(static_cast<unsigned char>(symbol))) {
            symbols.push_back(symbol);
        }
    }
    if (symbols.size() % 4 != 0) {
        return boost::none;
    }

    ByteBuffer data;
    data.reserve(symbols.size() / 4 * 3);
    for (std::size_t i = 0; i < symbols.size(); i += 4) {
        const bool last_quantum = i + 4 == symbols.size();
        std::uint32_t quantum = 0;
        std::size_t padding = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const char symbol = symbols[i + j];
            const int value = base64_value(symbol);
            if (symbol == '=' && last_quantum && j >= 2) {
                ++padding;
                quantum <<= 6;
            } else if (value < 0 || padding > 0) {
                return boost::none;
            } else {
                quantum = (quantum << 6) | value;
            }
        }
        data.push_back((quantum >> 16) & 0xff);
        if (padding < 2) {
            data.push_back((quantum >> 8) & 0xff);
        }
        if (padding < 1) {
            data.push_back(quantum & 0xff);
        }
    }
    return data;
}

} // namespace

std::string encode_pem(const std::string& label, const ByteBuffer& der)
{
    const std::string base64 = encode_base64(der);
    std::string pem = "-----BEGIN " + label + "-----\n";
    for (std::size_t i = 0; i < base64.size(); i += 64) {
        pem.append(base64, i, 64);
        pem.push_back('\n');
    }
    pem += "-----END " + label + "-----\n";
    return pem;
}

boost::optional<ByteBuffer> decode_pem(const std::string& label, const std::string& text)
{
    const std::string begin = "-----BEGIN " + label + "-----";
    const std::string end = "-----END " + label + "-----";
    const std::size_t begin_position = text.find(begin);
    if (begin_position == std::string::npos) {
        return boost::none;
    }
    const std::size_t data_position = begin_position + begin.size();
    const std::size_t end_position = text.find(end, data_position);
    if (end_position == std::string::npos) {
        return boost::none;
    }
    return decode_base64(text.substr(data_position, end_position - data_position));
}

} // namespace security
} // namespace vanetza
