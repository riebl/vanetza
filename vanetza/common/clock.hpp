#ifndef CLOCK_HPP_2FCBLXSJ
#define CLOCK_HPP_2FCBLXSJ

#include <chrono>
#include <cstdint>
#include <ratio>

namespace vanetza
{

class clock
{
public:
    typedef uint64_t rep;
    typedef std::ratio<1, 1000> period;
    typedef std::chrono::duration<rep, period> duration;
    typedef std::chrono::time_point<clock> time_point;

    static constexpr bool is_steady() { return true; }
};

} // namespace vanetza

#endif /* CLOCK_HPP_2FCBLXSJ */

