#include <vector>
#include <iostream>

#include "gtest/gtest.h"

#include "Base/Encoding.h"
#include "Crypto/Shamir.h"
#include "Core/MemoryRandomNumberGenerator.h"

static void create_shares_test(
        const std::string &secret,
        const uint8_t m,
        const uint8_t n,
        const std::string &random,
        const std::map<uint8_t, std::string> &expected_shares
) {

    const auto secret_bytes = Base::Encoding::decode_hex_any(secret);
    const auto entropy = Base::Encoding::decode_hex_any(random);

    Core::MemoryRandomNumberGenerator rng(entropy);

    const auto shares = Shamir::create_shares(rng, secret_bytes, m, n);

    EXPECT_EQ(shares.size(), expected_shares.size());

    for (std::size_t x = 1; x <= shares.size(); ++x)
    {
        EXPECT_EQ(shares.at(x), Base::Encoding::decode_hex_any(expected_shares.at(x)));
    }
}

static void recombine_shares_test(
        const std::string &expected_secret_hex,
        const uint8_t m,
        const std::map<uint8_t, std::string> &shares_hex
) {

    const auto expected_secret = Base::Encoding::decode_hex_any(expected_secret_hex);

    std::map<uint8_t, Base::ZBytes> shares;

    for (const auto &[x, share_hex] : shares_hex) {
        shares[x] = Base::Encoding::decode_hex_any(share_hex);
    }

    const auto recombined_secret = Shamir::recombine_shares(shares, m);

    EXPECT_EQ(recombined_secret, expected_secret);
}

TEST(Shamir, create_shares) {

    create_shares_test("7465737400", 2, 2,
                       "A87B3491B58BE31DBA42", {
       {1, "DC1E47E5B5" },
       {2, "3F931B4D71" },
    });

    create_shares_test("53414D5443", 2, 4,
                       "395D396C87CE75528C6691C7C0BF233AE7C96F8B", {
        {1, "6A1C7438C4" },
        {2, "21FB3F8C56" },
        {3, "18A606E0D1" },
        {4, "B72EA9FF69" },
    });

    create_shares_test("53414D5443", 3, 4,
                       "273A1A28AB9979BC06377C48595FF88195C2FB50", {
        {1, "4E737F9172" },
        {2, "F5D5526093" },
        {3, "E8E760A5A2" },
        {4, "429F849E06" },
    });

    create_shares_test("53414D5443", 4, 4,
                       "1A224C1EE9760A73A09D05774434672361D9ADF5", {
        {1, "27C094BB54" },
        {2, "B969F9F40E" },
        {3, "7EC7CD3250" },
        {4, "ABAF81828D" },
    });

    create_shares_test("546573742044617461", 2, 9,
                       "7FB4E8581EB75DC9453FE7837DD"
                       "C3036F50347B820B85C88059274"
                       "BA279E5EF11DF69B841F9A2636C"
                       "7AA3613EED2B8C94F8C12A3C0D9"
                       "9603BFA9CB7B7CFDF81927B1E01"
                       "B162ACF119BDE67FE7A6C9BDC7F", {
        {1, "2BD19B2C3EF33CBD24" },
        {2, "AA16B8C41C31DBFDEB" },
        {3, "D5A2509C02868634AE" },
        {4, "B383FE0F58AE0E7D6E" },
        {5, "CC371657461953B42B" },
        {6, "4DF035BF64DBB4F4E4" },
        {7, "3244DDE77A6CE93DA1" },
        {8, "81B27282D08BBF667F" },
        {9, "FE069ADACE3CE2AF3A" },
    });


    create_shares_test("0102030405060708090A0B0C0D0E0F", 3, 5,
                       "EC96740540B3E1FC9A914F6E5F7CCA51DB723202C9B881004F"
                       "66A28071974F36070E5A77DA6F79355B5A3D9CB932DE31B247"
                       "766B3F30E002FBFE9B415708F9811DE4C1011F13291AFF41D4", {
           {1, "7B73F0190E272493A03A7A8D242CE9" },
           {2, "ACFE7900583B52D877665415106787" },
           {3, "D68F8A1D531A7143DE562594394561" },
           {4, "3F99DDF4889BE16A29E2773E106863" },
           {5, "45E82EE983BAC2F180D206BF394A85" },
   });
}

TEST(Shamir, recombine_shares) {

    // 2/2

    recombine_shares_test("7465737400", 2, {
            {1, "DC1E47E5B5"},
            {2, "3F931B4D71"},
    });

    // 2/4

    recombine_shares_test("53414D5443", 2, {
            {1, "6A1C7438C4" },
            {2, "21FB3F8C56" },
            {3, "18A606E0D1" },
            {4, "B72EA9FF69" },
    });

    recombine_shares_test("53414D5443", 2, {
            {1, "6A1C7438C4" },
            {2, "21FB3F8C56" },
    });

    recombine_shares_test("53414D5443", 2, {
            {1, "6A1C7438C4" },
            {3, "18A606E0D1" },
    });

    recombine_shares_test("53414D5443", 2, {
            {1, "6A1C7438C4" },
            {4, "B72EA9FF69" },
    });

    recombine_shares_test("53414D5443", 2, {
            {2, "21FB3F8C56" },
            {3, "18A606E0D1" },
    });

    recombine_shares_test("53414D5443", 2, {
            {2, "21FB3F8C56" },
            {4, "B72EA9FF69" },
    });

    recombine_shares_test("53414D5443", 2, {
            {3, "18A606E0D1" },
            {4, "B72EA9FF69" },
    });

    // 3/4

    recombine_shares_test("53414D5443", 3, {
           {1, "4E737F9172" },
           {2, "F5D5526093" },
           {3, "E8E760A5A2" },
           {4, "429F849E06" },
    });

    recombine_shares_test("53414D5443", 3, {
            {2, "F5D5526093" },
            {3, "E8E760A5A2" },
            {4, "429F849E06" },
    });

    recombine_shares_test("53414D5443", 3, {
            {1, "4E737F9172" },
            {3, "E8E760A5A2" },
            {4, "429F849E06" },
    });

    recombine_shares_test("53414D5443", 3, {
            {1, "4E737F9172" },
            {2, "F5D5526093" },
            {4, "429F849E06" },
    });

    recombine_shares_test("53414D5443", 3, {
            {1, "4E737F9172" },
            {2, "F5D5526093" },
            {3, "E8E760A5A2" },
    });

    // 4/4

    recombine_shares_test("53414D5443", 4,  {
           {1, "27C094BB54" },
           {2, "B969F9F40E" },
           {3, "7EC7CD3250" },
           {4, "ABAF81828D" },
    });

    // 2/9

    recombine_shares_test("546573742044617461", 2, {
           {1, "2BD19B2C3EF33CBD24" },
           {2, "AA16B8C41C31DBFDEB" },
           {3, "D5A2509C02868634AE" },
           {4, "B383FE0F58AE0E7D6E" },
           {5, "CC371657461953B42B" },
           {6, "4DF035BF64DBB4F4E4" },
           {7, "3244DDE77A6CE93DA1" },
           {8, "81B27282D08BBF667F" },
           {9, "FE069ADACE3CE2AF3A" },
    });

    recombine_shares_test("546573742044617461", 2, {
            {1, "2BD19B2C3EF33CBD24" },
            {2, "AA16B8C41C31DBFDEB" },
    });

    recombine_shares_test("546573742044617461", 2, {
            {3, "D5A2509C02868634AE" },
            {4, "B383FE0F58AE0E7D6E" },
    });

    recombine_shares_test("546573742044617461", 2, {
            {5, "CC371657461953B42B" },
            {6, "4DF035BF64DBB4F4E4" },
    });

    recombine_shares_test("546573742044617461", 2, {
            {7, "3244DDE77A6CE93DA1" },
            {8, "81B27282D08BBF667F" },
            {9, "FE069ADACE3CE2AF3A" },
    });

    // 3/5

    recombine_shares_test("0102030405060708090A0B0C0D0E0F", 3, {
           {1, "7B73F0190E272493A03A7A8D242CE9" },
           {2, "ACFE7900583B52D877665415106787" },
           {3, "D68F8A1D531A7143DE562594394561" },
           {4, "3F99DDF4889BE16A29E2773E106863" },
           {5, "45E82EE983BAC2F180D206BF394A85" },
    });

    recombine_shares_test("0102030405060708090A0B0C0D0E0F", 3, {
            {1, "7B73F0190E272493A03A7A8D242CE9" },
            {2, "ACFE7900583B52D877665415106787" },
            {3, "D68F8A1D531A7143DE562594394561" },
    });

    recombine_shares_test("0102030405060708090A0B0C0D0E0F", 3, {
            {2, "ACFE7900583B52D877665415106787" },
            {3, "D68F8A1D531A7143DE562594394561" },
            {4, "3F99DDF4889BE16A29E2773E106863" },
    });

    recombine_shares_test("0102030405060708090A0B0C0D0E0F", 3, {
            {3, "D68F8A1D531A7143DE562594394561" },
            {4, "3F99DDF4889BE16A29E2773E106863" },
            {5, "45E82EE983BAC2F180D206BF394A85" },
    });

    recombine_shares_test("0102030405060708090A0B0C0D0E0F", 3, {
            {1, "7B73F0190E272493A03A7A8D242CE9" },
            {3, "D68F8A1D531A7143DE562594394561" },
            {5, "45E82EE983BAC2F180D206BF394A85" },
    });

    // 255/255

    recombine_shares_test("c8ff024ebaf299f5f6005958180e2c08", 255, {
            { 1, "d46e6990a0c3cf76c9f38683239e83a5" },
            { 2, "2aa4b37d0e04a59a358822135d6e37ed" },
            { 3, "f2716192ec8823b8e75d2198debc80e2" },
            { 4, "132844601337851a5a61e11f9cbdddb7" },
            { 5, "302a71fd0528886a665c1d01d9b70338" },
            { 6, "a9614f49a55daa30a5ae9c071b6374b8" },
            { 7, "28335f1918128f55ce3bd428aec112d8" },
            { 8, "785192f35436477c8c563b17b822e4cb" },
            { 9, "0366f6c2a2cf830e7a9e51e195eddb2d" },
            { 10, "ca191cfd3e7920cbc6e8f9e410659bd0" },
            { 11, "40434fea74414a0d7e5200d2b36da36a" },
            { 12, "40982640107f3a7a69c358829c9a5cad" },
            { 13, "a3e9401ecf3f753f5dc9122224a0459e" },
            { 14, "f6a9c6f497d8f38638bb0b654aaf1016" },
            { 15, "d38004d6613a016ef731904d8a16f1fc" },
            { 16, "b6b35e0d50ef3dd8011c95bf16b7fcb2" },
            { 17, "a8636ca58dccb33189f7dcc167444664" },
            { 18, "2bf2323264e99c0359024e7a953bcccc" },
            { 19, "729740f7ed6cc4eaadcd422a12a2d761" },
            { 20, "c23b58665b2c6052a434fd1296d6c080" },
            { 21, "a2cdc61e5068fad493230bec104dd17c" },
            { 22, "c3f7bbb0eb29404f0789afaa19145a89" },
            { 23, "c9b5fd7ace07a4f59190090c64ca8e09" },
            { 24, "65ce4358e391ad5d5b19e63fb4456f88" },
            { 25, "2a74f9125a345655e3a63c03abd75934" },
            { 26, "65d8073738ed89ed6720d89de7269cd3" },
            { 27, "43797403b414d849f514f371edb35ad7" },
            { 28, "98b503e106a16268cdea83bb621a7ead" },
            { 29, "9dac57a389287872c0a400907befb7b7" },
            { 30, "453d9252eeff2ee9b31da542f227d263" },
            { 31, "ac0db8501c1c655aa20c1fe08a41e409" },
            { 32, "a60f9affca9516a32efc2e98c5494433" },
            { 33, "05f5afc6fbca21efa6fdfeb0febfc568" },
            { 34, "bbb805b87d4506645bac89c10414b691" },
            { 35, "4e3cb19665120774cd89dfc22616323c" },
            { 36, "c8349b440cd67a283350da677b4a3ad0" },
            { 37, "5937b3a1396677b6723fc47d0e5ac037" },
            { 38, "39040c8f772ff1c97b05213fcfdb8a65" },
            { 39, "24a8dfce4fe5f1620316cbdc339f9c77" },
            { 40, "f9da1251083f89bf31ad3847df9670e1" },
            { 41, "51cd1bc6bad3f841a90b811ba046edf0" },
            { 42, "88e6bb2108371f663ad66d1ed0feb37b" },
            { 43, "398498624f179a1020d828e07d66fc53" },
            { 44, "7829143cdb9f0f7193e78e56fb17608c" },
            { 45, "e67a6ff72930d1c86db57312afca4a72" },
            { 46, "e5b5b09c5f8418dd96f8c52202ada5f9" },
            { 47, "a632d72ef63c68c6e3dc4e05f0b94830" },
            { 48, "bf6abac26b2550de80721b8b376700be" },
            { 49, "db3df283f2bcf29b3cfe59b53a8acfd3" },
            { 50, "37f0d0850fc2d7f44d1d1bdbc61307cc" },
            { 51, "76a9215c1ba9272ee809a62aedf363d5" },
            { 52, "7243dd489b3a75e2b04445be01be54f0" },
            { 53, "b38095abcfd5f54d4255aa72836d7ae9" },
            { 54, "34c7268b6de2c0d5fe36c0202a0ea983" },
            { 55, "54186395ae6402aca9eb330fb0a3c3bc" },
            { 56, "5cbd71b4483df38e3907f04eb3be4704" },
            { 57, "884e26dbfc80d6f1e344fa7de406ebcc" },
            { 58, "03710d5413a120146285cf82061ab59e" },
            { 59, "013d2ecae8c9f2369617e14ced5ceebe" },
            { 60, "ad63833b8e0edd4598c85bf674a4fad9" },
            { 61, "d8c69358af397e73dab8186334e3b040" },
            { 62, "2dc2822ab091c079f9f988bed6bfc146" },
            { 63, "5987481cba80cef9788f67b63561a2b9" },
            { 64, "d071f3a3e2f37dc74da728226c702870" },
            { 65, "f53c759ea0b8e980fe1adeb6ba5add86" },
            { 66, "8abed6ac9f54954de042688575d3757d" },
            { 67, "67a6038dec26b0017a26a6fd953b6f7c" },
            { 68, "6c153abf39111029ef71eee050d7e10d" },
            { 69, "197f7744e7c43794400ab3646c94155d" },
            { 70, "4d167593d79404d7be016188c14acc8c" },
            { 71, "1e08e0bdb13880a17cafc2821c6ed1c5" },
            { 72, "4711cd27b8286bcde467f7489c934d42" },
            { 73, "929cd2fe1016d9d3b9bf7cec2039da90" },
            { 74, "b777b026441a8d16c9ab87c5b6489fa3" },
            { 75, "348b7784d93ef25721a0f618e53e839a" },
            { 76, "aa82ce66819804b7d2d679cbf4f3181c" },
            { 77, "25dc8cf8fec27deaab3d55a2c83e5d8e" },
            { 78, "ae4a086b21626bb6de5ce930784bae8e" },
            { 79, "e0e67df2ba79072918ec5bf607ac2e82" },
            { 80, "c4359ffefa320a745345f4b75f0646e2" },
            { 81, "55cad341eac3623890ef081afbbfe57e" },
            { 82, "65562ce09bfec7e27f1d7162b9eefd19" },
            { 83, "522db5db5339c0b7ea84220a71dcbdad" },
            { 84, "3b42474caecdc9f26a5af54fa0731acf" },
            { 85, "ebe41153bf4df12ba3cf45ac69764777" },
            { 86, "324790d3fde8128223cd7453359cdcdd" },
            { 87, "e83cd20c3cbaeb8bd768c08f81bb55da" },
            { 88, "d719ffec1e19b4c8cacaa0cc0fdc7080" },
            { 89, "e7d00f7717f6fbef0b907459bc365988" },
            { 90, "f4447cc723e04b46d13ef29b9bc4029c" },
            { 91, "f9884ed5662f72c81ffeb100760fda6d" },
            { 92, "1f5813d486f36026ccb562247a4023d2" },
            { 93, "b48bc0a80deb142de3eb78b0d9582980" },
            { 94, "31fc7dc3b774ba9fa7341a4fe511889e" },
            { 95, "dffaa7d7a5fde538db15b8bac4bb7727" },
            { 96, "a0995c8805c8aa10db6405d79143e1c4" },
            { 97, "cf1bc8f4bb8e6deeef6f4163216b77ca" },
            { 98, "7159d40acc84b13131fbe2745b038b2f" },
            { 99, "7c21ea70180cb8508eab943b7eb92ba1" },
            { 100, "270f981451cdc01c4b6cc5b53bb31418" },
            { 101, "66f3c79698c5ae94b435110608b53f0a" },
            { 102, "71ad5bff9c355949208f21ffd1ea28d0" },
            { 103, "a0572323ba4acb2f7fae97ff1730c3ac" },
            { 104, "a8ba77095070efe01ae925a8c8ac6920" },
            { 105, "ed07756a50cc46824229c2be2747c2b2" },
            { 106, "e735d34abcab59d5048f2ef2de89c772" },
            { 107, "b2c87cc7a452b6476c94bac38137e1a2" },
            { 108, "1db6eddc5b7b3998ac0f3202b8015b17" },
            { 109, "c563f513cd2d6918d5c4a85e1fd6c39b" },
            { 110, "8f9a41280f44f022e27c08df2d151de9" },
            { 111, "863d2daa88c38d27a003d35c0f31f7d2" },
            { 112, "45694270c6401e18d22de5e765d6f90a" },
            { 113, "3329b66d8fdb5ae3d17431b4b2019fa2" },
            { 114, "0970fc4952e876c658ccdec7111b1897" },
            { 115, "c8bdf65545238b42a614249218a0d824" },
            { 116, "a9bbd0a4097104c120848717a336dc67" },
            { 117, "b895aad6d9b0576848b127dde28f1dca" },
            { 118, "a044f5402d174d17edd6c0f41e23f6df" },
            { 119, "ac48b296e4264b8c28df92cc4f69b61b" },
            { 120, "cd806c4f2c9500630035cd3f94691c88" },
            { 121, "597cbeb165c1138991a166ea2cccfb5d" },
            { 122, "571bd3bf5e3570a8c0660bc9d226ddb4" },
            { 123, "4eb77973ac7ad34ebd3d2ba99e0c4db2" },
            { 124, "25c29f6b61a84f1843dc3287ef062462" },
            { 125, "982a78d409c6e872ec1751d5f637fc0e" },
            { 126, "c5d0d02552d97c9cc24d56fc905503c6" },
            { 127, "f4247cde79e8ad97dbd29bca3d9a075b" },
            { 128, "63c54b5f74884de975186d559f85ed37" },
            { 129, "3a2e629367a59cd2ba5d0155d81d050a" },
            { 130, "154f4da36d75dea1ae827c556ef61be6" },
            { 131, "88529919e9a4e0a4d003672834968ba5" },
            { 132, "8547fe0a1be7114bae9de28efac672fe" },
            { 133, "3a37d07875135de43ca5da878abced74" },
            { 134, "a2d72a968a7b53f2f7911f51e18f93a3" },
            { 135, "6ef2548fe6054c810060b3d4da8dcad7" },
            { 136, "3e003e645691a66569229d6808ab4793" },
            { 137, "675f3eee42c72c3e49ef88c943bbdd45" },
            { 138, "cfd0561e402c39374d9867eabb4ec9e2" },
            { 139, "5a155d9a6c74c897d142b527e8ab77e9" },
            { 140, "ef29e69436ae3a6be6cc7242386d1efb" },
            { 141, "e3e25cc3339de0b5763bb1eb4d117197" },
            { 142, "337cff8e8b1c793b242d8c40ebda1eb6" },
            { 143, "9586b8b62513b24f5146b031654a9a26" },
            { 144, "6b478c733e070bec1a5a8b08331eea2a" },
            { 145, "8e93d318ff89be31c975531db2a35a60" },
            { 146, "b9cc8fefc4cb77649c132887fa119c47" },
            { 147, "b9f30accb9f5d5aba7bc07ad441bd3b9" },
            { 148, "e851d9e03c90776166c5ef187fc3727a" },
            { 149, "2e91b54469519993c5822be2887e6e25" },
            { 150, "de93d08cd609dd9a7998bc34841fced0" },
            { 151, "eee812512ab7c083f5380e8b0cd5efde" },
            { 152, "be6219d751b22e5d37bbe9068c3f0cf1" },
            { 153, "00ceccda767d919ba7e64c8349392e41" },
            { 154, "7dec06db451aebb787f0873288526a86" },
            { 155, "04a4c4bbfc811ab0ca70d04f9947fe68" },
            { 156, "334c3321b3e4a44aee403caa79fe9fe7" },
            { 157, "ff1d87b2f60a863e3963df030e9bbd29" },
            { 158, "6c5bd79a18fa1c3b114988849f1e0b5a" },
            { 159, "d80b243dee408305c0ad8038797e33f6" },
            { 160, "927e3456bfccfdfad9b9f5d5b2adce30" },
            { 161, "b2a6ff674fa3883648fe3bd32f1d936f" },
            { 162, "78193fd5ac0a1060a6aff0389e723211" },
            { 163, "f3fa3a0c1f024376e5341f1d62b5e2a9" },
            { 164, "bc7259701acd1c5dae8e30fcf9448d73" },
            { 165, "f04c4eb0d6934811935340ff0765f07a" },
            { 166, "354a8eeb419e4f4cadd6e62363729d7b" },
            { 167, "95dd151fc4eadbf9b5222f7945c24021" },
            { 168, "089f08691d7196af501290161f200025" },
            { 169, "db606122077ed940910b7ca9b842b55b" },
            { 170, "a4f2f7c18536669a8137d250cf87d159" },
            { 171, "eea5f4d8e5e237a48496040b21463523" },
            { 172, "ee71662e867bb2614be9c28619f55000" },
            { 173, "052fcae156fdd4737166f62d11c37768" },
            { 174, "4aa5ed62d33d3e9e1e9c885579395234" },
            { 175, "64ffef49b5e55b552fb88ebe5f0abfd2" },
            { 176, "de29882179e728a64da9c6cdde998acf" },
            { 177, "0f6bd596588a8eeb10425a518ce1ee71" },
            { 178, "df24e7dc852d62de51039d4629eb835b" },
            { 179, "8980319decbaafd575fba607fff2fcd4" },
            { 180, "9feea073d2c414d9bb629f88f4386a99" },
            { 181, "3802af67e1199af40c19119fcbd6ad59" },
            { 182, "55d2cc5a38ed94aaca2891657e52898e" },
            { 183, "b915342d28c99ae1a3ffccbba9219450" },
            { 184, "d198e2ddf8b492552281f0eaf69c9606" },
            { 185, "6ce07de02c6b7912428478a2e171f373" },
            { 186, "e352adf15b97fbd2317bb09ffad7e18b" },
            { 187, "bf3e5686f277ce46d2103f0310bade91" },
            { 188, "9d74e0d803af4e0e4f06ab57363fc3b3" },
            { 189, "3023272c33cd9e77dbcfb523237fd73b" },
            { 190, "dbdedd8825524a453378aa96adabe688" },
            { 191, "b2c766e8ce5af33744339b5e871e8a29" },
            { 192, "648b461370af8a605ae2bd4798e798ce" },
            { 193, "33ae02e1f359867659eeecb6d55ec279" },
            { 194, "6d64714e4e81c4634a5ec7c46ae6acf7" },
            { 195, "93d9fd9ed5d6b5f9139fef8468eeb29e" },
            { 196, "d103b1c9a0982910039f265ef574ff3b" },
            { 197, "01420c38a76c3975cdddcc7816338ebb" },
            { 198, "922c976b0f5698610a345b7061f56ac4" },
            { 199, "95a50322df85a9da0bd86ac62c510c5c" },
            { 200, "e1b52bf35b0a36220269ac3b9f3acfc2" },
            { 201, "250c60c8d4e46de7ef63fcbd46cb3403" },
            { 202, "dd015b23fea6bd07c255b76cd87b6446" },
            { 203, "d4b5350e2bb48825689fcdc6598f030b" },
            { 204, "d597cd4b0d3a0281b8b27f3b3bfb3a49" },
            { 205, "d3763d753050a5d1be92f75694198f2b" },
            { 206, "fe8e62c09db25872077a4c4de2bd29ae" },
            { 207, "3dac32ccfa3589359fec5e27fd78e18f" },
            { 208, "2b9de025d3d8ae474d4cc9643ae794be" },
            { 209, "7010c091b63962c765d8100542b439c5" },
            { 210, "bd9a45c5b8366aa5e6df2b5e19b1c0ad" },
            { 211, "a7829e6fd7007fde63083b979a1dd139" },
            { 212, "b2234456c4ed1218291eddd418fc1d96" },
            { 213, "ff30c6cda1ca2e45e7af21d6ed39b0e1" },
            { 214, "5aa653de2806ecdd4e713e4a76d5a836" },
            { 215, "47ea007977fabaa1e4cedd3bfe345215" },
            { 216, "14a64a1b8a2f8efce9ae961b8dbdaa69" },
            { 217, "6f05f11a8191bdbc9a852d077b98e021" },
            { 218, "a0fdfb5f839fdf0d3ace73203cd1867a" },
            { 219, "808a95ad9e91f0d5ef1f8bdb6f8c5915" },
            { 220, "e38a07f974eccb650f1cdf3b556c9aac" },
            { 221, "7507efbc121ca860fcd830bb7f30c142" },
            { 222, "bff603d53384abdf25729b95e51d56ff" },
            { 223, "87b5d6f2b622a7adf2e74c7ca758a774" },
            { 224, "e1dfcb908e0198996e0d1fa42e58db20" },
            { 225, "b70c9e938aba8bc9d0066b4340c49909" },
            { 226, "312e2c3e3c4b730a1cff9a6c2de2a917" },
            { 227, "7287f4b4fdbee288b4a3ffb4392f6934" },
            { 228, "48e29b762423ed2381edebf18744dfe1" },
            { 229, "6700b42910465e038b3b9cb2fd45dddb" },
            { 230, "1b9911d1d37eae43b0664bae41b48ad5" },
            { 231, "d6d073f27a2ec1cda15b2dfdbab1ab2a" },
            { 232, "f7866e7ffd224a0b4538ff8785634ab8" },
            { 233, "543f3b0222d7dfe8219bf57095034f36" },
            { 234, "8e68a94653690a5d34c9da743b933de5" },
            { 235, "f5e7d11fdb17f09aa9e7b4f05a0c9e9d" },
            { 236, "e9204044e886308a25455e78fe40db91" },
            { 237, "199142ef644b83351b97b62548197ec2" },
            { 238, "34ba75b2d3184e9ef53c6259d42ff10b" },
            { 239, "6a279f9c35edecea1845bdd454bebf32" },
            { 240, "6aa75e727ceb32b98d5b32bbaebdc0eb" },
            { 241, "3dafd27cb70f993cc63967c5dd72a5b4" },
            { 242, "def39957b6e8270db3fb63415328ab81" },
            { 243, "75a181564e52be3dbcb5fd6d6d90faed" },
            { 244, "1191859120311ec2b7f85c6df3bed8d9" },
            { 245, "fbc216cb3f2edcf1ddcec852130ae1a1" },
            { 246, "6b233cfd056982f420a02b484379278b" },
            { 247, "718282bda34617194c309ea13e74c691" },
            { 248, "d7bdf50425e7031306e6fc7d1addbf0a" },
            { 249, "fd0bade999bc78204eb0470ed085c6d2" },
            { 250, "54bde2a1384faf4418aa88835e1d095e" },
            { 251, "b16742e052b77acb4c73c46c18f9696e" },
            { 252, "361802d1373963a2291ab4ddbd60fae6" },
            { 253, "fcc4642917d246420eb128690d140b42" },
            { 254, "761482d7e8f562f07c97df4f48ec5601" },
            { 255, "62b4275a784197118391e4adf58b9513" },
    });
}
