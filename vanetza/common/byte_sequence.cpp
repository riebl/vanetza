#include <vanetza/common/byte_sequence.hpp>
#include <random>

namespace vanetza
{

ByteBuffer random_byte_sequence(std::size_t length, int seed)
{
    std::mt19937 rng;
    rng.seed(seed);
    ByteBuffer buffer;
    for (std::size_t i = 0; i < length; ++i) {
        buffer.push_back(rng());
    }
    return buffer;
}

} // namespace vanetza
