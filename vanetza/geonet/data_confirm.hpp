#ifndef DATA_CONFIRM_HPP_Z1WCMN8T
#define DATA_CONFIRM_HPP_Z1WCMN8T

#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <memory>

namespace vanetza
{
namespace geonet
{

struct DataRequest;
struct DataRequestWithArea;

struct DataConfirm
{
    enum class ResultCode {
        Accepted,
        Rejected_Max_SDU_Size,
        Rejected_Max_Lifetime,
        Rejected_Min_Repetition_Interval,
        Rejected_Unsupported_Traffic_Class,
        Rejected_Max_Geo_Area_Size,
        Rejected_Unspecified
    };

    DataConfirm() : result_code(ResultCode::Accepted) {}
    DataConfirm(ResultCode code) : result_code(code) {}
    bool accepted() const { return result_code == ResultCode::Accepted; }
    bool rejected() const { return !accepted(); }
    ResultCode result_code;
};

/**
 * XOR result code with DataConfirm's result code.
 * Replaces result code of DataConfirm only if new code is an error code.
 * \param lhs Operate on this DataConfirm
 * \param rhs XOR this ResultCode with lhs
 * \return reference to modified DataConfirm
 */
DataConfirm& operator ^=(DataConfirm& lhs, DataConfirm::ResultCode rhs);

DataConfirm::ResultCode validate_data_request(const DataRequest&, const MIB&);
DataConfirm::ResultCode validate_data_request(const DataRequestWithArea&, const MIB&);
DataConfirm::ResultCode validate_payload(const std::unique_ptr<DownPacket>&, const MIB&);

} // namespace geonet
} // namespace vanetza

#endif /* DATA_CONFIRM_HPP_Z1WCMN8T */

