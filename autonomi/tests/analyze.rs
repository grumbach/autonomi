// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ant_logging::LogBuilder;
use autonomi::client::payment::PaymentOption;
use autonomi::pointer::PointerTarget;
use autonomi::GraphEntryAddress;
use autonomi::{GraphEntry, Pointer, Scratchpad, client::analyze::Analysis};
use autonomi::{client::chunk::Chunk, Bytes, Client};
use eyre::Result;
use serial_test::serial;
use test_utils::evm::get_funded_wallet;

#[tokio::test]
#[serial]
async fn test_analyze_chunk() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze chunk", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let chunk = Chunk::new(Bytes::from("Chunk content example"));
    let (_cost, addr) = client.chunk_put(&chunk, payment_option).await?;
    assert_eq!(addr, *chunk.address());
    let chunk_addr = addr.to_hex();
    println!("Chunk: {chunk_addr}");

    let analysis = client.analyze_address(&chunk_addr, true).await?;
    assert_eq!(analysis, Analysis::Chunk(chunk));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_data() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze data", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let data = Bytes::from("Private data example");
    let (_cost, addr) = client.data_put(data, payment_option).await?;
    let data_addr = addr.to_hex();
    println!("Private Data (hex DataMapChunk): {data_addr}");

    let analysis = client.analyze_address(&data_addr, true).await?;
    assert!(matches!(analysis, Analysis::RawDataMap { .. }));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_public_data() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze public data", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let data = Bytes::from("Public data example");
    let (_cost, addr) = client.data_put_public(data, payment_option).await?;
    let public_data_addr = addr.to_hex();
    println!("Public Data (XorName): {public_data_addr}");

    let analysis = client.analyze_address(&public_data_addr, true).await?;
    assert!(matches!(analysis, Analysis::DataMap { .. }));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_graph_entry() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze graph entry", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let key = bls::SecretKey::random();
    let other_key = bls::SecretKey::random();
    let content = [0u8; 32];
    let graph_entry = GraphEntry::new(
        &key,
        vec![other_key.public_key()],
        content,
        vec![(other_key.public_key(), content)],
    );
    let (_cost, addr) = client.graph_entry_put(graph_entry.clone(), payment_option).await?;
    let graph_entry_addr = addr.to_hex();
    println!("Graph Entry: {graph_entry_addr}");
    let graph_entry_bls_pubkey = key.public_key().to_hex();
    println!("Graph Entry (bls pubkey): {graph_entry_bls_pubkey}");

    let analysis = client.analyze_address(&graph_entry_addr, true).await?;
    assert_eq!(analysis, Analysis::GraphEntry(graph_entry));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_pointer() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze pointer", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let target_addr = GraphEntryAddress::from_hex("b6f6ca699551882e2306ad9045e35c8837a3b99810af55ed358efe7166b7f6b4213ded09b200465f25d5d013fc7c35f9")?;
    let key = bls::SecretKey::random();
    let pointer = Pointer::new(&key, 0, PointerTarget::GraphEntryAddress(target_addr));
    let (_cost, addr) = client.pointer_put(pointer.clone(), payment_option).await?;
    let pointer_addr = addr.to_hex();
    println!("Pointer: {pointer_addr}");
    let pointer_bls_pubkey = key.public_key().to_hex();
    println!("Pointer (bls pubkey): {pointer_bls_pubkey}");

    let analysis = client.analyze_address(&pointer_addr, true).await?;
    assert_eq!(analysis, Analysis::Pointer(pointer));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_scratchpad() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze scratchpad", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let key = bls::SecretKey::random();
    let scratchpad = Scratchpad::new(&key, 0, &Bytes::from("Scratchpad content example"), 0);
    let (_cost, addr) = client.scratchpad_put(scratchpad.clone(), payment_option).await?;
    let scratchpad_addr = addr.to_hex();
    println!("Scratchpad: {scratchpad_addr}");
    let scratchpad_bls_pubkey = key.public_key().to_hex();
    println!("Scratchpad (bls pubkey): {scratchpad_bls_pubkey}");

    let analysis = client.analyze_address(&scratchpad_addr, true).await?;
    assert_eq!(analysis, Analysis::Scratchpad(scratchpad));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_register() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze register", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let key = bls::SecretKey::random();
    let value = Client::register_value_from_bytes(b"Register content example")?;
    let (_cost, addr) = client.register_create(&key, value, payment_option).await?;
    let register_addr = addr.to_hex();
    println!("Register: {register_addr}");
    let register_bls_pubkey = key.public_key().to_hex();
    println!("Register (bls pubkey): {register_bls_pubkey}");

    let analysis = client.analyze_address(&register_addr, true).await?;
    assert!(matches!(analysis, Analysis::Register { .. }));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_private_dir() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze private dir", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let path = "tests/file/test_dir/".into();
    let (_cost, archive_datamap) = client.dir_upload(path, payment_option.clone()).await?;
    let archive_datamap_addr = archive_datamap.to_hex();
    println!("Private Archive (DataMap): {archive_datamap_addr}");

    let analysis = client.analyze_address(&archive_datamap_addr, true).await?;
    assert!(matches!(analysis, Analysis::PrivateArchive { .. }));
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_analyze_public_dir() -> Result<()> {
    let _log_appender_guard = LogBuilder::init_single_threaded_tokio_test("analyze public dir", false);

    let client = Client::init_local().await?;
    let wallet = get_funded_wallet();
    let payment_option = PaymentOption::from(&wallet);

    let path = "tests/file/test_dir/".into();
    let (_cost, archive_addr) = client
        .dir_upload_public(path, payment_option)
        .await?;
    let archive_addr_str = archive_addr.to_hex();
    println!("Public Archive (XorName): {archive_addr_str}");

    let analysis = client.analyze_address(&archive_addr_str, true).await?;
    assert!(matches!(analysis, Analysis::PublicArchive { .. }));

    Ok(())
}

/*

Chunk: e39da9ea748f591b29d849f3a1b3bb84d1ff0b5efaa5dd8683713a533089ceba

Private Data (hex DataMapChunk): 81a54669727374939400dc00202f221cccd8cc903ecc86ccddcc86cca80a24ccf2cc9723cc9b760ccce55a3dcccf385475cc96ccdccc82ccd6cc891dccd3dc0020ccb4cc97ccf7633eccddccc23a616acc9dcce402cc8c0361cce14acce5cc9eccb0ccd439470b67cc926702ccedcca412069401dc0020ccb8cce44accf1cce85b6d73cce711ccc1cca4ccdeccb5cc9accbccca6ccdccce5cc9e39ccdf440d31cc9049cc951acc974a07dc0020277eccd0ccf5ccafccdfccadccda47ccbecc83106accd251cc9a612fcce22acc9f3534cc8eccfecc9a46ccef7c05ccf2cc8c069402dc0020ccf8cceccc86ccbb7ccc82ccd8ccd56275cccdcce058ccebcc9965ccc6cca113cc804d15ccee70ccfeccbfccd3ccfe48ccc9ccd2cc92dc00207d7c41ccd9ccb3cc8e687d6fccec15ccc4cc83cc82222e34cc963c2b75652a156202606352ccf517cccb08

Public Data (XorName): 5f762ea832f430dc98c38f5bc767177d2422812c87c28be7a868cf9a77cea783

Graph Entry: b6f6ca699551882e2306ad9045e35c8837a3b99810af55ed358efe7166b7f6b4213ded09b200465f25d5d013fc7c35f9

Graph Entry (bls pubkey): b6f6ca699551882e2306ad9045e35c8837a3b99810af55ed358efe7166b7f6b4213ded09b200465f25d5d013fc7c35f9

Pointer: af74a1ffbf553a8a39f4493455a0130cc5444f84224e7594d546c2d3beb58f28e8d5a42ea86aaa3e4dd4608c16c90356

Pointer (bls pubkey): af74a1ffbf553a8a39f4493455a0130cc5444f84224e7594d546c2d3beb58f28e8d5a42ea86aaa3e4dd4608c16c90356

Scratchpad: b1c6fa49f95bef4378de7c1cac026138ee424c21ec5c3458e3fdbec56e65433fccb351b87ce1015b2d3d93349c7c93e8

Scratchpad (bls pubkey): b1c6fa49f95bef4378de7c1cac026138ee424c21ec5c3458e3fdbec56e65433fccb351b87ce1015b2d3d93349c7c93e8

Register: 8a0e33a2f92b8b0b1817727371d5f97c4241d6776586306c9f93405ff09efc66313976915e130316604efd3648260843

Register (bls pubkey): 8a0e33a2f92b8b0b1817727371d5f97c4241d6776586306c9f93405ff09efc66313976915e130316604efd3648260843

Private Archive (DataMap): 81a54669727374939400dc0020cccbccc706ccc17f64cccecc9e7348ccbbccb70cccb87b6a5162cca3ccddccf8cc8accb9cc986bcc93cc9004ccce48585edc0020cce4cc9bcceb4a7fccd8393769675926ccfbcca60034cce8cc9151cc89ccd6ccf91ecc96cccfccaacc91ccc870cce8346fcd020e9401dc0020cc9fccb170ccefccdb384fcc8bcce8cce7ccd1cca9cca14d4cccd97e28cc84cc97cc8547735eccbecce4cccfccdd1ecccbcc8bccf8dc0020cca8ccdb1ecceb3a1ccccb42cca515ccbeccda29ccbc5dccb10eccf43975cc9accb1cc974b73cce9cceecc85ccf84c5bccc8cd020e9402dc0020ccbcccc4cca42b55ccd7ccc87c231d06ccd017ccbdcc9f3d135dccc2ccfdccd3ccfbccaf4ccce25b016e3cccbf7c74dc0020cce4ccb5705cccf9cc94263746cca77651ccd4520363cc94cce46c44cccbcc95cce2ccd07a0660ccceccdfcc96cce9cce0cd020e

Public Archive (XorName): 6a449d6f5e425325cf6857b7f5ab1176b993105220011b3f70e03e9cd2302a7b
 
 */