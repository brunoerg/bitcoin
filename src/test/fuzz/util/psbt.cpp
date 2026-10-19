// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/util/psbt.h>

#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <ios>
#include <span>
#include <vector>

using namespace util::hex_literals;

namespace {

constexpr std::array<uint8_t, 5> PSBT_MAGIC{'p', 's', 'b', 't', 0xff};

struct Record {
    //! Raw "<keytype><keydata>" bytes, excluding the length prefix.
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
};

//! A global, input or output map. All share the same record layout.
using Map = std::vector<Record>;

std::vector<uint8_t> ReadLengthPrefixed(SpanReader& s)
{
    const uint64_t len{ReadCompactSize(s)};
    if (len > s.size()) throw std::ios_base::failure("record exceeds buffer");
    std::vector<uint8_t> bytes(len);
    s.read(MakeWritableByteSpan(bytes));
    return bytes;
}

/**
 * Split the buffer into maps until it runs out. A map that is cut short is
 * dropped, but the maps before it are kept. Returns no maps if the magic is
 * missing.
 */
std::vector<Map> ParsePSBT(std::span<const uint8_t> buffer)
{
    std::vector<Map> maps;
    if (buffer.size() < PSBT_MAGIC.size() || !std::equal(PSBT_MAGIC.begin(), PSBT_MAGIC.end(), buffer.begin())) {
        return maps;
    }
    SpanReader s{buffer.subspan(PSBT_MAGIC.size())};
    try {
        while (!s.empty()) {
            Map map;
            while (true) {
                std::vector<uint8_t> key{ReadLengthPrefixed(s)};
                // A zero-length key is the separator that ends the map.
                if (key.empty()) break;
                map.push_back({std::move(key), ReadLengthPrefixed(s)});
            }
            maps.push_back(std::move(map));
        }
    } catch (const std::ios_base::failure&) {
    }
    return maps;
}

std::vector<uint8_t> SerializePSBT(const std::vector<Map>& maps)
{
    std::vector<uint8_t> out{PSBT_MAGIC.begin(), PSBT_MAGIC.end()};
    VectorWriter w{out, out.size()};
    for (const Map& map : maps) {
        for (const Record& rec : map) {
            w << rec.key << rec.value;
        }
        WriteCompactSize(w, 0);
    }
    return out;
}

//! Minimal valid PSBTv0: a global unsigned tx with 1 input and 1 output, followed by empty input/output maps.
std::vector<uint8_t> BuildPSBTv0Template()
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid{}, 0});
    tx.vout.emplace_back(0, CScript{});
    std::vector<uint8_t> tx_ser;
    VectorWriter{tx_ser, 0, TX_NO_WITNESS(tx)};

    std::vector<Map> maps(3);
    maps[0].push_back({{0x00}, std::move(tx_ser)}); // PSBT_GLOBAL_UNSIGNED_TX
    return SerializePSBT(maps);
}

//! Minimal valid PSBTv2 with 1 input and 1 output, required fields only.
std::vector<uint8_t> BuildPSBTv2Template()
{
    std::vector<Map> maps(3);
    maps[0].push_back({{0xFB}, {2, 0, 0, 0}}); // PSBT_GLOBAL_VERSION = 2
    maps[0].push_back({{0x02}, {2, 0, 0, 0}}); // PSBT_GLOBAL_TX_VERSION = 2
    maps[0].push_back({{0x04}, {1}});          // PSBT_GLOBAL_INPUT_COUNT = 1
    maps[0].push_back({{0x05}, {1}});          // PSBT_GLOBAL_OUTPUT_COUNT = 1

    maps[1].push_back({{0x0e}, std::vector<uint8_t>(32, 0)}); // PSBT_IN_PREVIOUS_TXID
    maps[1].push_back({{0x0f}, {0, 0, 0, 0}});                // PSBT_IN_OUTPUT_INDEX

    maps[2].push_back({{0x03}, std::vector<uint8_t>(8, 0)}); // PSBT_OUT_AMOUNT
    maps[2].push_back({{0x04}, {}});                         // PSBT_OUT_SCRIPT
    return SerializePSBT(maps);
}

enum class KeyData {
    NONE,   //!< single-byte key
    PUBKEY, //!< <keytype><33-byte compressed pubkey>
};

enum class ValueKind {
    RANDOM, //!< value_len random bytes
    TXOUT,  //!< <8-byte amount><compactsize script len><script>
};

struct KnownKey {
    uint8_t type;
    size_t value_len; //!< 0 => pick a random length
    KeyData key_data{KeyData::NONE};
    ValueKind value_kind{ValueKind::RANDOM};
};

//! The secp256k1 generator point, compressed. Pubkeys in keydata are validated, so random bytes would almost never pass.
constexpr auto VALID_PUBKEY{"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"_hex_u8};

struct KeyPools {
    std::span<const KnownKey> global;
    std::span<const KnownKey> input;
    std::span<const KnownKey> output;
};

// BIP 174 key types for a PSBTv0 input/output map. The global pool instead
// holds PSBTv2-only fields, which a v0 parser must reject.
constexpr KnownKey V0_GLOBAL_KEYS[]{
    {0xFB, 4}, // PSBT_GLOBAL_VERSION
    {0x02, 4}, // PSBT_GLOBAL_TX_VERSION
    {0x03, 4}, // PSBT_GLOBAL_FALLBACK_LOCKTIME
};
constexpr KnownKey V0_INPUT_KEYS[]{
    {0x01, 0, KeyData::NONE, ValueKind::TXOUT}, // PSBT_IN_WITNESS_UTXO
    {0x02, 72, KeyData::PUBKEY},                // PSBT_IN_PARTIAL_SIG
    {0x03, 4},                                  // PSBT_IN_SIGHASH_TYPE
    {0x04, 0},                                  // PSBT_IN_REDEEM_SCRIPT
    {0x05, 0},                                  // PSBT_IN_WITNESS_SCRIPT
    {0x06, 8, KeyData::PUBKEY},                 // PSBT_IN_BIP32_DERIVATION
    {0x07, 0},                                  // PSBT_IN_FINAL_SCRIPTSIG
    {0x08, 0},                                  // PSBT_IN_FINAL_SCRIPTWITNESS
};
constexpr KnownKey V0_OUTPUT_KEYS[]{
    {0x00, 0},                  // PSBT_OUT_REDEEM_SCRIPT
    {0x01, 0},                  // PSBT_OUT_WITNESS_SCRIPT
    {0x02, 8, KeyData::PUBKEY}, // PSBT_OUT_BIP32_DERIVATION
};

// Key types legal in a PSBTv2 map: the v2-only fields needed to get past the
// version/count checks that gate the v2 parsing path, plus the input/output
// fields shared with v0.
constexpr KnownKey V2_GLOBAL_KEYS[]{
    {0xFB, 4}, // PSBT_GLOBAL_VERSION
    {0x02, 4}, // PSBT_GLOBAL_TX_VERSION
    {0x03, 4}, // PSBT_GLOBAL_FALLBACK_LOCKTIME
    {0x04, 1}, // PSBT_GLOBAL_INPUT_COUNT
    {0x05, 1}, // PSBT_GLOBAL_OUTPUT_COUNT
    {0x06, 1}, // PSBT_GLOBAL_TX_MODIFIABLE
};
constexpr KnownKey V2_INPUT_KEYS[]{
    {0x01, 0, KeyData::NONE, ValueKind::TXOUT}, // PSBT_IN_WITNESS_UTXO
    {0x02, 72, KeyData::PUBKEY},                // PSBT_IN_PARTIAL_SIG
    {0x03, 4},                                  // PSBT_IN_SIGHASH_TYPE
    {0x04, 0},                                  // PSBT_IN_REDEEM_SCRIPT
    {0x05, 0},                                  // PSBT_IN_WITNESS_SCRIPT
    {0x06, 8, KeyData::PUBKEY},                 // PSBT_IN_BIP32_DERIVATION
    {0x07, 0},                                  // PSBT_IN_FINAL_SCRIPTSIG
    {0x08, 0},                                  // PSBT_IN_FINAL_SCRIPTWITNESS
    {0x0e, 32},                                 // PSBT_IN_PREVIOUS_TXID
    {0x0f, 4},                                  // PSBT_IN_OUTPUT_INDEX
    {0x10, 4},                                  // PSBT_IN_SEQUENCE
    {0x11, 4},                                  // PSBT_IN_REQUIRED_TIME_LOCKTIME
    {0x12, 4},                                  // PSBT_IN_REQUIRED_HEIGHT_LOCKTIME
};
constexpr KnownKey V2_OUTPUT_KEYS[]{
    {0x00, 0},                  // PSBT_OUT_REDEEM_SCRIPT
    {0x01, 0},                  // PSBT_OUT_WITNESS_SCRIPT
    {0x02, 8, KeyData::PUBKEY}, // PSBT_OUT_BIP32_DERIVATION
    {0x03, 8},                  // PSBT_OUT_AMOUNT
    {0x04, 0},                  // PSBT_OUT_SCRIPT
};

constexpr KeyPools V0_POOLS{V0_GLOBAL_KEYS, V0_INPUT_KEYS, V0_OUTPUT_KEYS};
constexpr KeyPools V2_POOLS{V2_GLOBAL_KEYS, V2_INPUT_KEYS, V2_OUTPUT_KEYS};

//! Bitcoin Core parses both versions, so pick the pools matching the PSBT_GLOBAL_VERSION the input declares.
const KeyPools& SelectPools(const std::vector<Map>& maps)
{
    const bool is_v2{std::ranges::any_of(maps.front(), [](const Record& rec) {
        return rec.key == std::vector<uint8_t>{0xFB} && rec.value == std::vector<uint8_t>{2, 0, 0, 0};
    })};
    return is_v2 ? V2_POOLS : V0_POOLS;
}

Record MakeKnownRecord(const KnownKey& k, InsecureRandomContext& rng)
{
    Record rec;
    rec.key = {k.type};
    if (k.key_data == KeyData::PUBKEY) {
        rec.key.insert(rec.key.end(), VALID_PUBKEY.begin(), VALID_PUBKEY.end());
    }
    const size_t len{k.value_len ? k.value_len : rng.randrange<size_t>(64)};
    if (k.value_kind == ValueKind::TXOUT) {
        rec.value = rng.randbytes<uint8_t>(8);
        VectorWriter{rec.value, rec.value.size(), rng.randbytes<uint8_t>(len)};
    } else {
        rec.value = rng.randbytes<uint8_t>(len);
    }
    return rec;
}

//! Apply one structure-aware mutation to maps in place.
void MutateMaps(std::vector<Map>& maps, const KeyPools& pools, InsecureRandomContext& rng)
{
    const size_t map_idx{rng.randrange(maps.size())};
    Map& map{maps[map_idx]};
    switch (rng.randrange(6)) {
    case 0: { // mutate an existing record's value bytes
        if (map.empty()) break;
        Record& rec{map[rng.randrange(map.size())]};
        const size_t old_size{rec.value.size()};
        rec.value.resize(old_size + 16);
        rec.value.resize(FuzzDefaultMutate(rec.value.data(), old_size, rec.value.size()));
        break;
    }
    case 1: { // mutate an existing record's key bytes
        if (map.empty()) break;
        Record& rec{map[rng.randrange(map.size())]};
        if (rec.key.empty()) break;
        // Leave room to grow, so keydata of other lengths can be reached.
        const size_t old_size{rec.key.size()};
        rec.key.resize(old_size + 16);
        rec.key.resize(FuzzDefaultMutate(rec.key.data(), old_size, rec.key.size()));
        break;
    }
    case 2: { // remove a record
        if (map.empty()) break;
        map.erase(map.begin() + rng.randrange(map.size()));
        break;
    }
    case 3: { // duplicate a record (exercises duplicate-key rejection paths)
        if (map.empty()) break;
        map.push_back(map[rng.randrange(map.size())]);
        break;
    }
    case 4: { // insert a well-known field of the detected version
        const std::span<const KnownKey> pool{std::array{pools.global, pools.input, pools.output}[rng.randrange(3)]};
        map.push_back(MakeKnownRecord(pool[rng.randrange(pool.size())], rng));
        break;
    }
    case 5: { // add or remove a whole map (grows/shrinks the apparent input/output count)
        if (maps.size() <= 1 || rng.randbool()) {
            maps.emplace_back();
        } else {
            maps.erase(maps.begin() + map_idx);
        }
        break;
    }
    }
}

} // namespace

size_t PSBTCustomMutator(uint8_t* data, size_t size, size_t max_size, unsigned int seed)
{
    InsecureRandomContext rng{seed};

    std::vector<Map> maps{ParsePSBT({data, size})};
    std::vector<uint8_t> out;
    if (maps.empty()) {
        out = rng.randbool() ? BuildPSBTv0Template() : BuildPSBTv2Template();
    } else {
        const KeyPools& pools{SelectPools(maps)};
        const int num_mutations{1 + rng.randrange(3)};
        for (int i{0}; i < num_mutations; ++i) {
            MutateMaps(maps, pools, rng);
        }
        out = SerializePSBT(maps);
    }
    out.resize(std::min(out.size(), max_size));
    std::memcpy(data, out.data(), out.size());
    return out.size();
}
