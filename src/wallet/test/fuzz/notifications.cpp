// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace {
const TestingSetup* g_setup;

void initialize_setup()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

class WalletSingleton {
public:
    static WalletSingleton& GetInstance() {
        static WalletSingleton instance;
        return instance;
    }

    void ResetWallets() {
        wallet_a.reset();
        wallet_b.reset();
    }

    CWallet& GetA() {
        if (!wallet_a) {
            InitializeWallets();
        }
        return *wallet_a;
    }
    CWallet& GetB() {
        if (!wallet_b) {
            InitializeWallets();
        }
        return *wallet_b;
    }

private:
    WalletSingleton() {
        InitializeWallets();
    }

    ~WalletSingleton() {
        ResetWallets();
    }

    WalletSingleton(const WalletSingleton&) = delete;
    WalletSingleton& operator=(const WalletSingleton&) = delete;

    void InitializeWallets() {
        gArgs.ForceSetArg("-keypool", "0"); // Avoid timeout in TopUp()
        const auto& node{g_setup->m_node};
        wallet_a = std::make_unique<CWallet>(node.chain.get(), "a", CreateMockableWalletDatabase());
        wallet_b = std::make_unique<CWallet>(node.chain.get(), "b", CreateMockableWalletDatabase());
        assert(wallet_a);
        assert(wallet_b);
        Chainstate* chainstate = &node.chainman->ActiveChainstate();
        {
            LOCK(wallet_a->cs_wallet);
            wallet_a->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet_a->SetupDescriptorScriptPubKeyMans();
            wallet_a->SetLastBlockProcessed(chainstate->m_chain.Height(), chainstate->m_chain.Tip()->GetBlockHash());
        }
        {
            LOCK(wallet_b->cs_wallet);
            wallet_b->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet_b->SetupDescriptorScriptPubKeyMans();
            wallet_b->SetLastBlockProcessed(chainstate->m_chain.Height(), chainstate->m_chain.Tip()->GetBlockHash());
        }
    }

    std::unique_ptr<CWallet> wallet_a;
    std::unique_ptr<CWallet> wallet_b;
};

CScript GetScriptPubKey(FuzzedDataProvider& fuzzed_data_provider, CWallet& wallet)
{
    auto type{fuzzed_data_provider.PickValueInArray(OUTPUT_TYPES)};
    util::Result<CTxDestination> op_dest{util::Error{}};
    if (fuzzed_data_provider.ConsumeBool()) {
        op_dest = wallet.GetNewDestination(type, "");
    } else {
        op_dest = wallet.GetNewChangeDestination(type);
    }
    return GetScriptForDestination(*Assert(op_dest));
}

FUZZ_TARGET(wallet_notifications, .init = initialize_setup)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    // The total amount, to be distributed to the wallets a and b in txs
    // without fee. Thus, the balance of the wallets should always equal the
    // total amount.
    const auto total_amount{ConsumeMoney(fuzzed_data_provider)};

    WalletSingleton::GetInstance().ResetWallets();
    CWallet& wallet_a{WalletSingleton::GetInstance().GetA()};
    CWallet& wallet_b{WalletSingleton::GetInstance().GetB()};

    // Keep track of all coins in this test.
    // Each tuple in the chain represents the coins and the block created with
    // those coins. Once the block is mined, the next tuple will have an empty
    // block and the freshly mined coins.
    using Coins = std::set<std::tuple<CAmount, COutPoint>>;
    std::vector<std::tuple<Coins, CBlock>> chain;
    {
        // Add the initial entry
        chain.emplace_back();
        auto& [coins, block]{chain.back()};
        coins.emplace(total_amount, COutPoint{uint256::ONE, 1});
    }
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 200)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                auto& [coins_orig, block]{chain.back()};
                // Copy the coins for this block and consume all of them
                Coins coins = coins_orig;
                while (!coins.empty()) {
                    // Create a new tx
                    CMutableTransaction tx{};
                    // Add some coins as inputs to it
                    auto num_inputs{fuzzed_data_provider.ConsumeIntegralInRange<int>(1, coins.size())};
                    CAmount in{0};
                    while (num_inputs-- > 0) {
                        const auto& [coin_amt, coin_outpoint]{*coins.begin()};
                        in += coin_amt;
                        tx.vin.emplace_back(coin_outpoint);
                        coins.erase(coins.begin());
                    }
                    // Create some outputs spending all inputs, without fee
                    LIMITED_WHILE(in > 0 && fuzzed_data_provider.ConsumeBool(), 100)
                    {
                        const auto out_value{ConsumeMoney(fuzzed_data_provider, in)};
                        in -= out_value;
                        auto& wallet{fuzzed_data_provider.ConsumeBool() ? wallet_a : wallet_b};
                        tx.vout.emplace_back(out_value, GetScriptPubKey(fuzzed_data_provider, wallet));
                    }
                    // Spend the remaining input value, if any
                    auto& wallet{fuzzed_data_provider.ConsumeBool() ? wallet_a : wallet_b};
                    tx.vout.emplace_back(in, GetScriptPubKey(fuzzed_data_provider, wallet));
                    // Add tx to block
                    block.vtx.emplace_back(MakeTransactionRef(tx));
                }
                // Mine block
                const uint256& hash = block.GetHash();
                interfaces::BlockInfo info{hash};
                info.prev_hash = &block.hashPrevBlock;
                info.height = chain.size();
                info.data = &block;
                // Ensure that no blocks are skipped by the wallet by setting the chain's accumulated
                // time to the maximum value. This ensures that the wallet's birth time is always
                // earlier than this maximum time.
                info.chain_time_max = std::numeric_limits<unsigned int>::max();
                wallet_a.blockConnected(info);
                wallet_b.blockConnected(info);
                // Store the coins for the next block
                Coins coins_new;
                for (const auto& tx : block.vtx) {
                    uint32_t i{0};
                    for (const auto& out : tx->vout) {
                        coins_new.emplace(out.nValue, COutPoint{tx->GetHash(), i++});
                    }
                }
                chain.emplace_back(coins_new, CBlock{});
            },
            [&] {
                if (chain.size() <= 1) return; // The first entry can't be removed
                auto& [coins, block]{chain.back()};
                if (block.vtx.empty()) return; // Can only disconnect if the block was submitted first
                // Disconnect block
                const uint256& hash = block.GetHash();
                interfaces::BlockInfo info{hash};
                info.prev_hash = &block.hashPrevBlock;
                info.height = chain.size() - 1;
                info.data = &block;
                wallet_a.blockDisconnected(info);
                wallet_b.blockDisconnected(info);
                chain.pop_back();
            });
        auto& [coins, first_block]{chain.front()};
        if (!first_block.vtx.empty()) {
            // Only check balance when at least one block was submitted
            const auto bal_a{GetBalance(wallet_a).m_mine_trusted};
            const auto bal_b{GetBalance(wallet_b).m_mine_trusted};
            assert(total_amount == bal_a + bal_b);
        }
    }
}
} // namespace
} // namespace wallet
