use bdk::{
    bitcoin::{hashes::Hash, Address, BlockHash, Network},
    chain::{
        indexed_tx_graph::InsertTxItem,
        local_chain::{self, CheckPoint},
        BlockId, ConfirmationTimeAnchor, TxGraph,
    },
    wallet::{self, AddressIndex},
    SignOptions, Wallet,
};
use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{Auth, Client, RpcApi},
    Emission, EmittedBlock, Emitter,
};
use bdk_file_store::Store;
use std::str::FromStr;
use std::sync::mpsc::sync_channel;

const DB_MAGIC: &str = "bdk-wallet-rpc-example";
const FALLBACK_HEIGHT: u32 = 2476300;
const CHANNEL_BOUND: usize = 100;
const SEND_AMOUNT: u64 = 5000;
const LOOKAHEAD: u32 = 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::temp_dir().join("bdk-wallet-rpc-example");
    let db = Store::<bdk::wallet::ChangeSet>::new_from_path(DB_MAGIC.as_bytes(), db_path)?;
    let external_descriptor = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
    let internal_descriptor = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

    let mut wallet = Wallet::new(
        external_descriptor,
        Some(internal_descriptor),
        db,
        Network::Testnet,
    )?;

    let address = wallet.get_address(AddressIndex::New);
    println!("Generated Address: {}", address);

    let balance = wallet.get_balance();
    println!("Wallet balance before syncing: {} sats", balance.total());

    print!("Syncing...");

    let client = Client::new(
        "127.0.0.1:18332",
        Auth::UserPass("bitcoin".to_string(), "password".to_string()),
    )?;

    println!(
        "Connected to Bitcoin Core RPC at {:?}",
        client.get_blockchain_info().unwrap()
    );

    let rpc_client = Client::new(
        "127.0.0.1:18332",
        Auth::UserPass("bitcoin".to_string(), "password".to_string()),
    )?;

    println!(
        "Connected to Bitcoin Core RPC at {:?}",
        client.get_blockchain_info().unwrap()
    );

    wallet.set_lookahead_for_all(LOOKAHEAD);
    let (chan, recv) = sync_channel::<(Emission<EmittedBlock>, u32)>(CHANNEL_BOUND);
    let prev_cp = wallet.latest_checkpoint();
    let start_height = prev_cp
        .as_ref()
        .map_or(FALLBACK_HEIGHT, |cp| cp.height().saturating_sub(10));

    let join_handle = std::thread::spawn(move || -> anyhow::Result<()> {
        let mut tip_height = Option::<u32>::None;

        let mut emissions = Emitter::new(&rpc_client, start_height).into_iterator::<EmittedBlock>();
        for r in &mut emissions {
            let emission = r?;
            let is_mempool = emission.is_mempool();

            if tip_height.is_none() || is_mempool {
                tip_height = Some(rpc_client.get_block_count()? as u32);
            }
            chan.send((emission, tip_height.expect("must have tip height")))?;
        }

        Ok(())
    });

    for (emission, tip_height) in recv {
        let chain_update = match &emission {
            Emission::Mempool(_) => None,
            Emission::Block(EmittedBlock { block, height }) => {
                let this_id = BlockId {
                    height: *height,
                    hash: block.block_hash(),
                };
                let tip = if block.header.prev_blockhash == BlockHash::all_zeros() {
                    CheckPoint::new(this_id)
                } else {
                    CheckPoint::new(BlockId {
                        height: height - 1,
                        hash: block.header.prev_blockhash,
                    })
                    .extend(core::iter::once(this_id))
                    .expect("must construct checkpoint")
                };

                Some(local_chain::Update {
                    tip,
                    introduce_older_blocks: false,
                })
            }
        };
        let update_tip_height = chain_update.as_ref().map(|u| u.tip.height());

        let tx_graph_update: Vec<InsertTxItem<Option<ConfirmationTimeAnchor>>> = match &emission {
            Emission::Mempool(txs) => txs.iter().map(|tx| (&tx.tx, None, Some(tx.time))).collect(),
            Emission::Block(b) => {
                let anchor = ConfirmationTimeAnchor {
                    anchor_block: BlockId {
                        height: b.height,
                        hash: b.block.block_hash(),
                    },
                    confirmation_height: b.height,
                    confirmation_time: b.block.header.time as _,
                };
                b.block
                    .txdata
                    .iter()
                    .map(move |tx| (tx, Some(anchor), None))
                    .collect()
            }
        };

        let filtered_txs = wallet.filter_for_relevant_txs(tx_graph_update);
        let mut tx_graph = TxGraph::default();
        for (tx, anchors, seen_at) in filtered_txs {
            tx_graph.insert_tx(tx.clone());
            if let Some(seen_at) = seen_at {
                tx_graph.insert_seen_at(tx.txid(), seen_at);
            }
            for anchor in anchors {
                tx_graph.insert_anchor(tx.txid(), anchor);
            }
        }
        let mut wallet_update = wallet::Update::default();

        wallet_update.graph = tx_graph;
        wallet_update.chain = chain_update;
        wallet.apply_update(wallet_update);
    }

    wallet.commit()?;

    let _ = join_handle
        .join()
        .expect("failed to join chain source thread");

    let balance = wallet.get_balance();
    println!("Wallet balance after syncing: {} sats", balance.total());

    if balance.total() < SEND_AMOUNT {
        println!(
            "Please send at least {} sats to the receiving address",
            SEND_AMOUNT
        );
        std::process::exit(0);
    }

    let faucet_address = Address::from_str("tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6")?
        .require_network(Network::Testnet)?;

    let mut tx_builder = wallet.build_tx();
    tx_builder
        .add_recipient(faucet_address.script_pubkey(), SEND_AMOUNT)
        .enable_rbf();

    let mut psbt = tx_builder.finish()?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    assert!(finalized);

    let tx = psbt.extract_tx();
    let client = Client::new(
        "127.0.0.1:18332",
        Auth::UserPass("bitcoin".to_string(), "password".to_string()),
    )?;
    client.send_raw_transaction(&tx)?;
    println!("Tx broadcasted! Txid: {}", tx.txid());

    Ok(())
}
