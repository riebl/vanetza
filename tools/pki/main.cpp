#include "main.hpp"
#include "authorization.hpp"
#include "certificate_filesystem_storage.hpp"
#include "cpoc.hpp"
#include "credential_filesystem_storage.hpp"
#include "dc_command.hpp"
#include "enrolment.hpp"
#include "exception.hpp"
#include "http.hpp"
#include "key_command.hpp"
#include "openssl_security_module.hpp"
#include "printing.hpp"
#include "prune_command.hpp"
#include "station.hpp"
#include "station_config_filesystem.hpp"
#include "trust_list_filesystem_storage.hpp"
#include "xdg.hpp"
#include <CLI/CLI.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <iostream>
#include <locale>

using namespace vanetza::pki;

int main(int argc, char** argv)
{
    CLI::App app("Vanetza PKI tool");
    MainConfig config;
    config.config_path = xdg_config_home() / "vanetza";
    config.data_path = xdg_data_home() / "vanetza" / "pki";

    auto initialize_storage = [&config]() {
        config.credentials = std::make_shared<CredentialFilesystemStorage>(config.data_path / "keys");
        config.security = std::make_shared<OpenSslSecurityModule>(config.credentials);
        const std::filesystem::path certs_dir = config.data_path / "certificates";
        config.root_ca = std::make_shared<CertificateFilesystemStorage>(config.security, certs_dir, ".rca");
        config.enrolment_credentials =
            std::make_shared<CertificateFilesystemStorage>(config.security, certs_dir, ".ec");
        config.tickets = std::make_shared<CertificateFilesystemStorage>(config.security, certs_dir, ".at");
        config.tlm = std::make_shared<CertificateFilesystemStorage>(config.security, certs_dir, ".tlm");
        config.authorization_authorities =
            std::make_shared<CertificateFilesystemStorage>(config.security, certs_dir, ".aa");
        config.enrolment_authorities =
            std::make_shared<CertificateFilesystemStorage>(config.security, certs_dir, ".ea");
        config.trust_lists = std::make_shared<TrustListFilesystemStorage>(config.security, config.data_path / "ctls");
        config.crl_store = std::make_shared<CrlFilesystemStore>(config.security, config.data_path / "crls");
        config.station = std::make_shared<StationConfigurationFilesystem>(config.data_path);
        if (auto root_ca = config.station->get_root_ca()) {
            config.root_ca_hid8 = *root_ca;
            config.dc_url = lookup_dc_url(config.data_path / "ectl.ctl", *root_ca).value_or("");
        } else {
            config.root_ca_hid8 = HashedId8 {};
            config.dc_url.clear();
        }
    };

    const auto default_config_file = config.config_path / "pki.cfg";
    auto config_option = app.set_config("--config", default_config_file.string());
    config_option->description("PKI configuration file");
    config_option->envname("VANETZA_PKI_CONFIG");

    auto data_option = app.add_option("--data", config.data_path);
    data_option->description("PKI data directory");
    data_option->default_str(config.data_path.string());
    data_option->envname("VANETZA_PKI_DATA");
    data_option->type_name("");
    data_option->check([](const std::string& path) -> std::string {
        auto status = std::filesystem::status(path);
        if (std::filesystem::exists(status) && !std::filesystem::is_directory(status)) {
            return "PKI data path exists but is not a directory";
        }
        return {};
    });
    // Storage derives from config.data_path, which CLI11 binds during parse
    // (from --data, env, or config file). Build it once that value is final.
    app.parse_complete_callback(initialize_storage);

    app.require_subcommand(1);
    app.add_subcommand(build_authorization_command(config));
    app.add_subcommand(build_cpoc_command(config));
    app.add_subcommand(build_dc_command(config));
    app.add_subcommand(build_enrolment_command(config));
    app.add_subcommand(build_key_command());
    app.add_subcommand(build_print_command());
    app.add_subcommand(build_prune_command(config));
    app.add_subcommand(build_station_command(config));

    std::cout.imbue(std::locale(std::cout.getloc(), new boost::posix_time::time_facet("%Y-%m-%d %H:%M:%S")));

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    } catch (const UsageError& e) {
        std::cerr << "Usage: " << e.what() << "\n";
        if (!e.remedy().empty()) {
            std::cerr << "Hint:  " << e.remedy() << "\n";
        }
        return 2;
    } catch (const VerificationFailure& e) {
        std::cerr << "Verification failed: " << e.what() << "\n";
        return 3;
    } catch (const DecodingFailure& e) {
        std::cerr << "Decoding failed: " << e.what() << "\n";
        return 1;
    } catch (const HttpException& e) {
        std::cerr << "HTTP error: " << e << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred\n";
        return 1;
    }

    return 0;
}
