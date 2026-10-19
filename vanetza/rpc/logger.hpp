#pragma once

namespace vanetza
{
namespace rpc
{

class Logger
{
public:
    virtual void error(const char* context, const char* message) = 0;
    virtual void debug(const char* context, const char* message) = 0;

    virtual ~Logger() = default;
};

#define VANETZA_RPC_LOG_ERROR(logger, context, message) \
    if (logger != nullptr) { \
        logger->error(context, message); \
    }
#define VANETZA_RPC_LOG_DEBUG(logger, context, message) \
    if (logger != nullptr) { \
        logger->debug(context, message); \
    }

} // namespace rpc
} // namespace vanetza

