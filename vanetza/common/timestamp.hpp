#ifndef TIMESTAMP_HPP_5WAFSYEU
#define TIMESTAMP_HPP_5WAFSYEU

#include <time.h>

namespace vanetza
{

class Timestamp
{
public:
    typedef timespec internal_t;

    Timestamp();
    explicit Timestamp(const internal_t&);
    explicit operator internal_t*() { return &mInternal; }
    explicit operator const internal_t*() const { return &mInternal; }

    friend bool operator==(const Timestamp&, const Timestamp&);
    friend bool operator<(const Timestamp&, const Timestamp&);

private:
    internal_t mInternal;
};

void setMonotonic(Timestamp&);
double calcIntervalSeconds(const Timestamp& start, const Timestamp& stop);
double calcIntervalMilliseconds(const Timestamp& start, const Timestamp& stop);

} // namespace vanetza

#endif /* TIMESTAMP_HPP_5WAFSYEU */

