#include <gtest/gtest.h>
#include <vanetza/common/factory.hpp>
#include <string>
#include <utility>

using namespace vanetza;

using StringFactory = Factory<std::string>;

StringFactory::Function make(const std::string& value)
{
    return [value]() { return std::unique_ptr<std::string> { new std::string(value) }; };
}

TEST(Factory, create)
{
    StringFactory factory;
    EXPECT_TRUE(factory.add("a", make("a")));
    EXPECT_TRUE(factory.add("b", make("b")));
    EXPECT_FALSE(factory.add("a", make("again")));

    ASSERT_NE(nullptr, factory.create("a"));
    EXPECT_EQ("a", *factory.create("a"));
    EXPECT_EQ(nullptr, factory.create("c"));
    EXPECT_EQ(nullptr, factory.create());
}

TEST(Factory, configure_default)
{
    StringFactory factory;
    factory.add("a", make("a"));
    factory.add("b", make("b"));

    EXPECT_TRUE(factory.configure_default("b"));
    ASSERT_NE(nullptr, factory.create());
    EXPECT_EQ("b", *factory.create());

    // unknown implementation resets default
    EXPECT_FALSE(factory.configure_default("c"));
    EXPECT_EQ(nullptr, factory.create());
}

TEST(Factory, copy_without_default)
{
    StringFactory original;
    original.add("a", make("a"));

    StringFactory copy_constructed(original);
    EXPECT_EQ(nullptr, copy_constructed.create());

    StringFactory copy_assigned;
    copy_assigned = original;
    EXPECT_EQ(nullptr, copy_assigned.create());
}

TEST(Factory, copy_with_default)
{
    StringFactory original;
    original.add("a", make("a"));
    original.configure_default("a");

    StringFactory copy_constructed(original);
    StringFactory copy_assigned;
    copy_assigned = original;

    // overwrite original's implementations: copies must not be affected
    StringFactory other;
    other.add("a", make("other"));
    original = other;

    for (StringFactory* copy : { &copy_constructed, &copy_assigned }) {
        auto created = copy->create();
        ASSERT_NE(nullptr, created);
        EXPECT_EQ("a", *created);
    }
}

TEST(Factory, move_without_default)
{
    StringFactory original;
    original.add("a", make("a"));

    StringFactory moved(std::move(original));
    EXPECT_EQ(nullptr, moved.create());
    EXPECT_NE(nullptr, moved.create("a"));
}
