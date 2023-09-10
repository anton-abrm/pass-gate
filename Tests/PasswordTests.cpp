#include <vector>

#include "gtest/gtest.h"
#include "Password/Password.h"

static void decode_hhhs_test(const Base::ZString &encoded, const Base::ZBytes& expected) {
    EXPECT_EQ(Password::decode_hhhs(encoded), expected);
}

static void encode_hhhs_test(const Base::ZBytes& bytes, const Base::ZString &expected) {
    EXPECT_EQ(Password::encode_hhhs(bytes), expected);
}

TEST(Password, decode_hhhh) {
    decode_hhhs_test("Pa$$wrd!", { 0x35, 0x8e, 0xba, 0xb2, 0x76, 0xf8 });
}

TEST(Password, encode_hhhh) {
    encode_hhhs_test( { 0x35, 0x8e, 0xba, 0xb2, 0x76, 0xf8 }, "Pa$$wrd!");
}


