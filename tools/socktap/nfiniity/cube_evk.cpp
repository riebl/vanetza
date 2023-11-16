#include "cube_evk.hpp"

namespace po = boost::program_options;

void vanetza::nfiniity::add_cube_evk_options(po::options_description& options)
{
    options.add_options()
        ("cube-ip", po::value<std::string>()->default_value("127.0.0.1"), "cube evk's ip address")
    ;
}