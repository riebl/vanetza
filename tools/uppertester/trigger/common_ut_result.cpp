#include "common_ut_result.hpp"

void serialize(OutputArchive& ar, const UtResult& result)
{
    ar << result.message_type;
    ar << result.result;
}
