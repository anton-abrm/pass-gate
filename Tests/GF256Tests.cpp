#include <vector>

#include "gtest/gtest.h"
#include "Crypto/GF256.h"

TEST(GF256, add) {
    EXPECT_EQ(GF256::add(0x53, 0xca), 0x99);
}

TEST(GF256, subtract) {
    EXPECT_EQ(GF256::subtract(0x53, 0xca), 0x99);
}

TEST(GF256, multiply) {
    EXPECT_EQ(GF256::multiply(0x53, 0xca), 0x01);
}

TEST(GF256, divide) {
    EXPECT_EQ(GF256::divide(0x01, 0x53), 0xca);
    EXPECT_EQ(GF256::divide(0x01, 0xca), 0x53);
}