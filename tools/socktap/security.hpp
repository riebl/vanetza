#ifndef SECURITY_HPP_FV13ZIYA
#define SECURITY_HPP_FV13ZIYA

#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/security_entity.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <memory>

std::unique_ptr<vanetza::security::SecurityEntity>
create_security_entity(const boost::program_options::variables_map&, const vanetza::Runtime&, vanetza::PositionProvider&);

void add_security_options(boost::program_options::options_description&);

#endif /* SECURITY_HPP_FV13ZIYA */

