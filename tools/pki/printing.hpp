#pragma once

#include "CLI/App.hpp"
#include <memory>

namespace vanetza
{
namespace pki
{

std::shared_ptr<CLI::App> build_print_command();

} // namespace pki
} // namespace vanetza
