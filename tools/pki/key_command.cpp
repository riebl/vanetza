#include "key_command.hpp"
#include "exception.hpp"
#include "filesystem.hpp"
#include "keys.hpp"
#include "pem.hpp"
#include <vanetza/security/public_key.hpp>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <string>

namespace vanetza
{
namespace pki
{

namespace
{

const std::map<std::string, KeyType> key_type_map = {
    { "NistP256", KeyType::NistP256 },
    { "BrainpoolP256r1", KeyType::BrainpoolP256r1 },
    { "BrainpoolP384r1", KeyType::BrainpoolP384r1 }
};

struct Context
{
    std::function<void()> action;
    std::filesystem::path path; // --out for generate, --in for print
    KeyType type = KeyType::BrainpoolP256r1;
    bool force = false;
};

std::string key_type_name(KeyType type)
{
    for (const auto& entry : key_type_map) {
        if (entry.second == type) {
            return entry.first;
        }
    }
    return "Unspecified";
}

void print_public_key(const PublicKey& pub)
{
    std::cout << "Key type: " << key_type_name(pub.type) << "\n";
    std::cout << "Canonical public key: " << security::canonical_hexstring(pub) << "\n";
}

void generate_keyfile(Context& ctx)
{
    if (std::filesystem::exists(ctx.path) && !ctx.force) {
        throw UsageError("key file already exists: " + ctx.path.string(), "pass --force to overwrite");
    }

    PrivateKey priv = generate_private_key(ctx.type);
    write_pem_private_key(priv, ctx.path);

    std::cout << "Wrote " << ctx.path.string() << "\n";
    print_public_key(derive_public_key(priv));
}

void print_keyfile(Context& ctx)
{
    auto priv = parse_pem_private_key(read(ctx.path));
    if (!priv) {
        throw UsageError("could not read an EC private key from " + ctx.path.string(), "expecting a PEM-encoded EC key");
    }
    print_public_key(derive_public_key(*priv));
}

} // namespace

std::shared_ptr<CLI::App> build_key_command()
{
    auto ctx = std::make_shared<Context>();
    auto app = std::make_shared<CLI::App>("EC key generation", "key");

    auto generate = app->add_subcommand("generate", "generate an EC private key (PEM) for enrolment");
    generate->alias("gen");
    generate->add_option("--out,-o", ctx->path, "output PEM file")->required();
    generate->add_flag("--force", ctx->force, "overwrite an existing key file");
    generate->add_option("--key-type", ctx->type, "type of generated key")
        ->default_val(KeyType::BrainpoolP256r1)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(key_type_map, CLI::ignore_case));
    generate->callback([ctx]() { ctx->action = [ctx]() { generate_keyfile(*ctx); }; });

    auto print = app->add_subcommand("print", "print the canonical public key of an existing PEM key file");
    print->add_option("--in,-i", ctx->path, "input PEM file")->required()->check(CLI::ExistingFile);
    print->callback([ctx]() { ctx->action = [ctx]() { print_keyfile(*ctx); }; });

    app->require_subcommand(1);
    app->final_callback([ctx]() {
        if (ctx->action) {
            ctx->action();
        }
    });
    return app;
}

} // namespace pki
} // namespace vanetza
