#ifndef TRANSMISSION_HPP_SDC4RMQE
#define TRANSMISSION_HPP_SDC4RMQE

#include <vanetza/access/data_rates.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/profile.hpp>
#include <cstddef>

namespace vanetza
{
namespace dcc
{

class Transmission
{
public:
    virtual Profile profile() const = 0;
    virtual const access::DataRateG5* data_rate() const = 0;
    virtual std::size_t body_length() const = 0;
    virtual Clock::duration channel_occupancy() const;
    virtual ~Transmission() = default;
};

struct TransmissionLite : public Transmission
{
    constexpr TransmissionLite(Profile dp, std::size_t len) : m_profile(dp), m_length(len) {}

    Profile m_profile;
    std::size_t m_length = 0; /*< length in bytes of MAC frame body */
    const access::DataRateG5* m_data_rate = nullptr;

    Profile profile() const override { return m_profile; }
    const access::DataRateG5* data_rate() const override { return m_data_rate; }
    std::size_t body_length() const override { return m_length; }
};

} // namespace dcc
} // namespace vanetza

#endif /* TRANSMISSION_HPP_SDC4RMQE */

