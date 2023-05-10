// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/setup_common.h>
#include <vector>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/types.h>
#include <wallet/wallet.h>

using wallet::CWallet;

namespace wallet {
namespace {
const TestingSetup* g_setup;
static std::unique_ptr<CWallet> g_wallet_ptr;
static Chainstate* g_chainstate = nullptr;

void initialize_setup()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
    const auto& node{g_setup->m_node};
    g_chainstate = &node.chainman->ActiveChainstate();
    g_wallet_ptr = std::make_unique<CWallet>(node.chain.get(), "", CreateMockableWalletDatabase());
}

FUZZ_TARGET_INIT(receive, initialize_setup)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    CWallet& wallet = *g_wallet_ptr;
    {
        LOCK(wallet.cs_wallet);
        wallet.SetLastBlockProcessed(g_chainstate->m_chain.Height(), g_chainstate->m_chain.Tip()->GetBlockHash());
    }

    const CScript script{ConsumeScript(fuzzed_data_provider)};
    CTxOut tx_out{ConsumeMoney(fuzzed_data_provider), script};
    // Set up nValue to not cause "value out of range" error
    tx_out.nValue = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, MAX_MONEY);

    const std::optional<CMutableTransaction> opt_mutable_transaction{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider)};
    if (!opt_mutable_transaction) {
        return;
    }
    CMutableTransaction random_mutable_transaction{*opt_mutable_transaction};

    for (auto& vout : random_mutable_transaction.vout) {
        vout.nValue = fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, MAX_MONEY);
    }

    const std::optional<uint256> hash = ConsumeDeserializable<uint256>(fuzzed_data_provider);
    if (!hash) {
        return;
    }
    TxStateUnrecognized tx_state_unrecognized(*hash, fuzzed_data_provider.ConsumeIntegralInRange<int>(-1, 1));
    TxState tx_state(TxStateInterpretSerialized(tx_state_unrecognized));
    CTransaction transaction{random_mutable_transaction};
    (void)GetAddressBalances(wallet);

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                (void)ScriptIsChange(wallet, script);
            },
            [&] {
                (void)OutputIsChange(wallet, tx_out);
            },
            [&] {
                (void)TxGetChange(wallet, transaction);
            },
            [&] {
                (void)GetBalance(wallet, fuzzed_data_provider.ConsumeIntegral<int>(), fuzzed_data_provider.ConsumeBool());
            },
            [&] {
                (void)GetAddressBalances(wallet);
            },
            [&] {
                (void)GetAddressGroupings(wallet);
            });
    }

    std::shared_ptr<CTransaction> shared_tx = std::make_shared<CTransaction>(transaction);
    std::shared_ptr<const CTransaction> cst_shared_tx = std::const_pointer_cast<const CTransaction>(shared_tx);
    CWalletTx wallet_tx(cst_shared_tx, tx_state);
    const auto mine{fuzzed_data_provider.PickValueInArray({isminetype::ISMINE_NO, isminetype::ISMINE_WATCH_ONLY, isminetype::ISMINE_SPENDABLE, isminetype::ISMINE_USED, isminetype::ISMINE_ALL, isminetype::ISMINE_ALL_USED})};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                (void)CachedTxIsTrusted(wallet, wallet_tx);
            },
            [&] {
                (void)AllInputsMine(wallet, transaction, mine);
            },
            [&] {
                (void)OutputGetCredit(wallet, tx_out, mine);
            },
            [&] {
                (void)TxGetCredit(wallet, transaction, mine);
            },
            [&] {
                (void)CachedTxGetCredit(wallet, wallet_tx, mine);
            },
            [&] {
                (void)CachedTxGetDebit(wallet, wallet_tx, mine);
            },
            [&] {
                (void)CachedTxGetChange(wallet, wallet_tx);
            },
            [&] {
                (void)CachedTxGetImmatureCredit(wallet, wallet_tx, mine);
            },
            [&] {
                (void)CachedTxGetAvailableCredit(wallet, wallet_tx, mine);
            },
            [&] {
                (void)CachedTxIsFromMe(wallet, wallet_tx, mine);
            });
    }
}
} // namespace
} // namespace wallet
