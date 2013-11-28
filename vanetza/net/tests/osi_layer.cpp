#include <gtest/gtest.h>
#include <vanetza/net/osi_layer.hpp>

using namespace vanetza;

TEST(OsiLayer, ordering) {
    EXPECT_LT(OsiLayer::Physical, OsiLayer::Link);
    EXPECT_LT(OsiLayer::Link, OsiLayer::Network);
    EXPECT_LT(OsiLayer::Network, OsiLayer::Transport);
    EXPECT_LT(OsiLayer::Transport, OsiLayer::Session);
    EXPECT_LT(OsiLayer::Session, OsiLayer::Presentation);
    EXPECT_LT(OsiLayer::Presentation, OsiLayer::Application);

    EXPECT_EQ(min_osi_layer(), OsiLayer::Physical);
    EXPECT_EQ(max_osi_layer(), OsiLayer::Application);
}

TEST(OsiLayer, comparison) {
    EXPECT_LT(OsiLayer::Physical, OsiLayer::Link);
    EXPECT_GT(OsiLayer::Link, OsiLayer::Physical);
    EXPECT_EQ(OsiLayer::Physical, OsiLayer::Physical);
    EXPECT_NE(OsiLayer::Physical, OsiLayer::Link);
    EXPECT_LE(OsiLayer::Physical, OsiLayer::Physical);
    EXPECT_GE(OsiLayer::Link, OsiLayer::Link);
}

TEST(OsiLayer, list) {
    auto list = osi_layers;
    ASSERT_EQ(list.size(), 7);

    auto it = list.begin();
    EXPECT_EQ(OsiLayer::Physical, *it++);
    EXPECT_EQ(OsiLayer::Link, *it++);
    EXPECT_EQ(OsiLayer::Network, *it++);
    EXPECT_EQ(OsiLayer::Transport, *it++);
    EXPECT_EQ(OsiLayer::Session, *it++);
    EXPECT_EQ(OsiLayer::Presentation, *it++);
    EXPECT_EQ(OsiLayer::Application, *it++);
    EXPECT_EQ(list.end(), it);

    auto prev = list.begin();
    for (auto it = prev + 1; it != list.end(); prev = it, ++it) {
        EXPECT_LT(*prev, *it);
    }
}

