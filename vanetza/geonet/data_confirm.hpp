#ifndef DATA_CONFIRM_HPP_Z1WCMN8T
#define DATA_CONFIRM_HPP_Z1WCMN8T

namespace vanetza
{
namespace geonet
{

struct DataConfirm
{
    enum class ResultCode {
        ACCEPTED,
        REJECTED_MAX_SDU_SIZE,
        REJECTED_MAX_LIFETIME,
        REJECTED_MIN_REPETITION_INTERVAL,
        REJECTED_UNSUPPORTED_TRAFFIC_CLASS,
        REJECTED_MAX_GEO_AREA_SIZE,
        REJECTED_UNSPECIFIED
    };

    DataConfirm() : result_code(ResultCode::REJECTED_UNSPECIFIED) {}
    DataConfirm(ResultCode code) : result_code(code) {}
    bool accepted() const { return result_code == ResultCode::ACCEPTED; }
    bool rejected() const { return !accepted(); }
    ResultCode result_code;
};

} // namespace geonet
} // namespace vanetza

#endif /* DATA_CONFIRM_HPP_Z1WCMN8T */

