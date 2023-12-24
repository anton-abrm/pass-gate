#include "gtest/gtest.h"

#include "PGS/V1/Package.h"
#include "PGS/V1/SignatureEntropySourceInfo.h"

static void parse_and_render_test(const std::string &text) {

    const auto package = PGS::V1::Package::parse(text);

    EXPECT_TRUE(package.has_value());

    const std::string text_produced = package.value()->to_string();

    EXPECT_EQ(text_produced, text);
}

TEST(Package, parse_and_render) {
    parse_and_render_test("pgs-v1.sign-v2-123456.enc-v2.AQID");
    parse_and_render_test("pgs-v1.bip39-v1-123456.enc-v2.AQID");
    parse_and_render_test("pgs-v1.bip39-v2-123456.enc-v2.AQID");
    parse_and_render_test("pgs-v1.rand.enc-v1.AQID");
    parse_and_render_test("pgs-v1.rand.enc-v2.AQID");
}
