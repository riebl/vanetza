#include <gtest/gtest.h>
#include <vanetza/common/object_container.hpp>

using namespace vanetza;

struct ObjectA
{
    int a = 1;
};

struct ObjectB
{
    int b = 2;
};

struct ObjectC
{
    int c = 3;
};

template<typename T>
std::unique_ptr<T> create_unique()
{
    return std::unique_ptr<T> { new T() };
}


TEST(ObjectContainer, size)
{
    ObjectContainer c;
    EXPECT_EQ(0, c.size());

    c.insert(create_unique<ObjectA>());
    EXPECT_EQ(1, c.size());

    c.insert(create_unique<ObjectA>());
    EXPECT_EQ(1, c.size());

    c.insert(create_unique<ObjectB>());
    EXPECT_EQ(2, c.size());

    c.clear();
    EXPECT_EQ(0, c.size());
}

TEST(ObjectContainer, insert)
{
    ObjectContainer c;
    EXPECT_TRUE(c.insert(create_unique<ObjectA>()));
    EXPECT_FALSE(c.insert(create_unique<ObjectA>()));
    EXPECT_TRUE(c.insert(create_unique<ObjectB>()));
}

TEST(ObjectContainer, find)
{
    ObjectContainer c;
    EXPECT_EQ(nullptr, c.find<ObjectA>());

    auto a = create_unique<ObjectA>();
    ObjectA* pa = a.get();
    auto b = create_unique<ObjectB>();
    ObjectB* pb = b.get();

    c.insert(std::move(a));
    c.insert(std::move(b));
    EXPECT_EQ(pa, c.find<ObjectA>());
    EXPECT_EQ(pb, c.find<ObjectB>());
}

TEST(ObjectContainer, erase)
{
    ObjectContainer c;
    c.insert(create_unique<ObjectA>());
    ASSERT_EQ(1, c.size());
    c.erase<ObjectB>();
    EXPECT_EQ(1, c.size());
    c.erase<ObjectA>();
    EXPECT_EQ(0, c.size());

    c.insert(create_unique<ObjectA>());
    c.insert(create_unique<ObjectB>());
    c.insert(create_unique<ObjectC>());
    c.erase<ObjectB>();
    EXPECT_EQ(2, c.size());
    EXPECT_NE(nullptr, c.find<ObjectA>());
    EXPECT_EQ(nullptr, c.find<ObjectB>());
    EXPECT_NE(nullptr, c.find<ObjectC>());
}

TEST(ObjectContainer, move)
{
    ObjectContainer c1;
    c1.insert(create_unique<ObjectA>());
    c1.insert(create_unique<ObjectB>());
    c1.insert(create_unique<ObjectC>());
    ASSERT_EQ(3, c1.size());

    auto* pa = c1.find<ObjectA>();
    auto* pb = c1.find<ObjectB>();
    auto* pc = c1.find<ObjectC>();

    ObjectContainer c2 = std::move(c1);
    EXPECT_EQ(0, c1.size());
    EXPECT_EQ(3, c2.size());
    EXPECT_EQ(pa, c2.find<ObjectA>());
    EXPECT_EQ(pb, c2.find<ObjectB>());
    EXPECT_EQ(pc, c2.find<ObjectC>());
}

TEST(ObjectContainer, get)
{
    ObjectContainer c;
    EXPECT_EQ(nullptr, c.find<ObjectA>());
    ObjectA& a = c.get<ObjectA>();
    EXPECT_EQ(1, a.a);
}

