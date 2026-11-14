#include <vanetza/security/persistence/key_reference.hpp>
#include <vanetza/security/persistence/tests/temporary_file.hpp>
#include <gtest/gtest.h>
#include <filesystem>
#include <system_error>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::persistence;

class KeyReferenceFileTest : public TemporaryFileTest
{
};

TEST_F(KeyReferenceFileTest, load_reverses_save)
{
    const KeyReference reference { ByteBuffer { 0x01, 0x02, 0x03 } };
    EXPECT_FALSE(save_key_reference(path, reference));
    const expected<KeyReference> loaded = load_key_reference(path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(reference.data, loaded->data);
}

TEST_F(KeyReferenceFileTest, saving_replaces_existing_file)
{
    write("previous content");
    EXPECT_FALSE(save_key_reference(path, KeyReference { ByteBuffer { 0x01 } }));
    EXPECT_EQ((ByteBuffer { 0x01 }), read());
}

TEST_F(KeyReferenceFileTest, saved_file_is_accessible_by_owner_only)
{
    // a file existing with broader permissions is restricted as well
    write("previous");
    std::filesystem::permissions(path, std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
        std::filesystem::perms::others_read);
    EXPECT_FALSE(save_key_reference(path, KeyReference { ByteBuffer { 0x01 } }));

    const std::filesystem::perms owner_only = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    EXPECT_EQ(owner_only, std::filesystem::status(path).permissions());
}

TEST_F(KeyReferenceFileTest, empty_reference_is_malformed)
{
    EXPECT_EQ(std::errc::invalid_argument, save_key_reference(path, KeyReference {}));
    write(ByteBuffer {});
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_key_reference(path).error());
}

TEST_F(KeyReferenceFileTest, file_errors_are_reported)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, load_key_reference(path).error());
    EXPECT_EQ(std::errc::no_such_file_or_directory,
        save_key_reference(missing_path, KeyReference { ByteBuffer { 0x01 } }));
}
