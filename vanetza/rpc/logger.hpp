#pragma once

namespace vanetza
{
namespace rpc
{

class Logger
{
public:
    virtual void error(const char* module, const char* message) = 0;
    virtual void debug(const char* module, const char* message) = 0;

    virtual ~Logger() = default;
};

#define VANETZA_RPC_LOG_ERROR(logger, module, message) \
    if (logger != nullptr) { \
        logger->error(module, message); \
    }
#define VANETZA_RPC_LOG_DEBUG(logger, module, message) \
    if (logger != nullptr) { \
        logger->debug(module, message); \
    }

} // namespace rpc
} // namespace vanetza

