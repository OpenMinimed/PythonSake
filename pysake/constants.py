from pysake.keys import KeyDatabase

LOGGER_NAME = "pysake" # maybe create a common logging instance here?

KEYDB_G4_CGM = KeyDatabase.from_bytes(bytes.fromhex("5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326"))
KEYDB_PUMP_EXTRACTED = KeyDatabase.from_bytes(bytes.fromhex("f75995e70401011bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c"))
KEYDB_PUMP_HARDCODED = KeyDatabase.from_bytes(bytes.fromhex("c2cdfdd1040101fce36ed66ef21def3b0763975494b239038ebe8606f79a9bf00d9f11b6db04c7c0434787cbf00d5476289c22288e2105ae40e01391837f9476fa5003895c5a1afe35662a2a6211826af016eebe30e4ba"))

AVAILABLE_KEYS = [
    KEYDB_G4_CGM,
    KEYDB_PUMP_EXTRACTED,
    KEYDB_PUMP_HARDCODED
]

CGM_TEST_MSGS = [
    bytes.fromhex("02015f0edcd0c2af98705bed6c8172856d860402"),
    bytes.fromhex("a579868377f401ae083405ef88cc0962d6079a04"),
    bytes.fromhex("77f3fb85b079310455fd8f47ddaf81ab49defc7b"),
    bytes.fromhex("7f57c1ac4e12d21b46cfaf03f9dbd4877d0a7d76"),
    bytes.fromhex("ef54ef03ad398363825fd434e69cd829630056fa"),
    bytes.fromhex("2f22c383cf264fa4ebc5b10dc8a2c8a4b000619e"),
]

CGM_TEST_KEYDB = KEYDB_G4_CGM


__PUMP_TEST_MSGS_1 = [ # 780g_pairing_with_mobile.pcapng
    bytes.fromhex("0401e2f09017a98f9f01cc56492fbacd4576e92b"),
    bytes.fromhex("42060e9f344e9312016ee8854d357f659b6b00ba"),
    bytes.fromhex("fdeeb13d04c3f18d272630ebeabe7c3a4d4d27b9"),
    bytes.fromhex("c02cec4ffb99affcb553a10fa6c55bb13d9fbacf"),
    bytes.fromhex("157d8e90214418a0e3d5f0517eebf4a82e00c02e"),
    bytes.fromhex("9b36f393b296fa84a757809859fc84a5c300d59b")
]

__PUMP_TEST_MSGS_2 = [
    bytes.fromhex("040131395205055606f9f7dcd6b257cde879d1d8"),
    bytes.fromhex("2a449f70b5156ed301406b185dd3d2d8ae976776"),
    bytes.fromhex("9c87e425cb9835c816242ce1133fd03904195c3e"),
    bytes.fromhex("dfd807a905c9a8bedafc0e3f30436d2deef5c8d7"),
    bytes.fromhex("1079db3924d2a8b4ed2033aca9104eedec008fdf"),
    bytes.fromhex("33f381971e76211eac3bd7cbf680648140001e83"),
]

__PUMP_TEST_MSGS_3 = [ # 2022-07-24 pairing-2.ble.decrypted.pcap
    bytes.fromhex("0401cc849f8f1fe9c44db69c284d20563c2624c9"),
    bytes.fromhex("4d2514c0b7993df7012ee651a48ebd27e223cf1b"),
    bytes.fromhex("dffe7eb3ebe76c561760c2f6abc4c66250387645"),
    bytes.fromhex("193670f903109c31db2beb945f91b930122cd289"),
    bytes.fromhex("88282a01627a871a8cd62d70b9840f844a0019bb"),
    bytes.fromhex("ebe84f24495c13b3f633d9f0f5e444dc7800edf4")
]

PUMP_TEST_MSGS = __PUMP_TEST_MSGS_2
PUMP_TEST_KEYDB = KEYDB_PUMP_EXTRACTED