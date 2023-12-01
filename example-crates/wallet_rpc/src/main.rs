use bdk::{
    bitcoin::{Address, Network},
    wallet::{AddressIndex, Wallet},
    SignOptions,
};
use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{
        bitcoincore_rpc_json::{
            ScanBlocksOptions, ScanBlocksRequest, ScanBlocksRequestDescriptor, ScanBlocksResult,
        },
        Auth, Client, RpcApi,
    },
    Emitter,
};
use bdk_file_store::Store;
use std::{str::FromStr, time::Duration};

const DB_MAGIC: &str = "bdk-rpc-wallet-example";
const SEND_AMOUNT: u64 = 5000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let db_path = std::env::temp_dir().join("bdk-rpc-example");
    let db = Store::<bdk::wallet::ChangeSet>::new_from_path(DB_MAGIC.as_bytes(), db_path)?;

    let external_descriptor = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)";
    let internal_descriptor = "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)";

    if args.len() < 6 {
        println!("Usage: wallet_rpc <RPC_URL> <RPC_USER> <RPC_PASS> <LOOKAHEAD> <FALLBACK_HEIGHT>");
        std::process::exit(1);
    }

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

    let rpc_client = Client::new_with_timeout(
        &args[1],
        Auth::UserPass(args[2].clone(), args[3].clone()),
        Duration::from_secs(3600),
    )?;

    println!(
        "Connected to Bitcoin Core RPC at {:?}",
        rpc_client.get_blockchain_info().unwrap()
    );

    let external_descriptor = ScanBlocksRequestDescriptor::Extended {
        desc: external_descriptor.to_string(),
        range: None,
    };
    let internal_descriptor = ScanBlocksRequestDescriptor::Extended {
        desc: internal_descriptor.to_string(),
        range: None,
    };
    let descriptors = &[external_descriptor, internal_descriptor];
    let request = ScanBlocksRequest {
        scanobjects: descriptors,
        start_height: None,
        stop_height: None,
        filtertype: None,
        options: Some(ScanBlocksOptions {
            filter_false_positives: Some(true),
        }),
    };
    let res: ScanBlocksResult = rpc_client.scan_blocks_blocking(request)?;
    println!("scanblocks result: {:?}", res);

    wallet.set_lookahead_for_all(args[4].parse::<u32>()?)?;

    let chain_tip = wallet.latest_checkpoint();
    let mut emitter = match chain_tip {
        Some(cp) => Emitter::from_checkpoint(&rpc_client, cp),
        None => Emitter::from_height(&rpc_client, args[5].parse::<u32>()?),
    };

    for bh in res.relevant_blocks {
        // self.get_relevant_txs(bh, &conn);
        let block = rpc_client.get_block(&bh)?;
        let height: u32 = block.bip34_block_height()?.try_into().unwrap();
        println!("adding block height {} to wallet", height);
        wallet.apply_block_relevant(block.clone(), height)?;
        wallet.commit()?;
    }

    // while let Some((height, block)) = emitter.next_block()? {
    //     println!("Applying block {} at height {}", block.block_hash(), height);
    //     wallet.apply_block_relevant(block, height)?;
    //     wallet.commit()?;
    // }

    let unconfirmed_txs = emitter.mempool()?;
    println!("Applying unconfirmed transactions: ...");
    wallet.batch_insert_relevant_unconfirmed(unconfirmed_txs.iter().map(|(tx, time)| (tx, *time)));
    wallet.commit()?;

    let balance = wallet.get_balance();
    println!("Wallet balance after syncing: {} sats", balance.total());

    if balance.total() < SEND_AMOUNT {
        println!(
            "Please send at least {} sats to the receiving address",
            SEND_AMOUNT
        );
        std::process::exit(1);
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
    rpc_client.send_raw_transaction(&tx)?;
    println!("Tx broadcasted! Txid: {}", tx.txid());

    Ok(())
}
