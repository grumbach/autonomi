// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::access::cached_payments;
use crate::actions::NetworkContext;
use crate::args::max_fee_per_gas::{MaxFeePerGasParam, get_max_fee_per_gas_from_opt_param};
use crate::exit_code::{ExitCodeError, FEES_ERROR, IO_ERROR, upload_exit_code};
use crate::utils::collect_upload_summary;
use crate::wallet::load_wallet;
use autonomi::client::analyze::Analysis;
use autonomi::client::merkle_payments::{MerkleFilePutError, MerklePaymentOption};
use autonomi::client::payment::PaymentOption;
use autonomi::files::UploadError;
use autonomi::networking::{Quorum, RetryStrategy};
use autonomi::{Client, ClientOperatingStrategy, TransactionConfig};
use color_eyre::Section;
use color_eyre::eyre::{Context, Result, eyre};
use std::path::PathBuf;

const MAX_ADDRESSES_TO_PRINT: usize = 3;

pub async fn cost(file: &str, network_context: NetworkContext) -> Result<()> {
    let client = crate::actions::connect_to_network(network_context)
        .await
        .map_err(|(err, _)| err)?;

    println!("Getting upload cost...");
    info!("Calculating cost for file: {file}");
    let cost = client
        .file_cost(&PathBuf::from(file))
        .await
        .wrap_err("Failed to calculate cost for file")?;

    println!("Estimate cost to upload file: {file}");
    println!("Total cost: {cost}");
    info!("Total cost: {cost} for file: {file}");
    Ok(())
}

pub async fn upload(
    file: &str,
    public: bool,
    no_archive: bool,
    network_context: NetworkContext,
    max_fee_per_gas_param: Option<MaxFeePerGasParam>,
    retry_failed: u64,
) -> Result<(), ExitCodeError> {
    let config = ClientOperatingStrategy::new();

    let mut client =
        crate::actions::connect_to_network_with_config(network_context, config).await?;

    // Configure client with retry_failed setting
    if retry_failed != 0 {
        println!(
            "🔄 Retry mode enabled - will retry failed chunks until successful or exceeds the limit."
        );
        client = client.with_retry_failed(retry_failed);
    }

    let mut wallet = load_wallet(client.evm_network()).map_err(|err| (err, IO_ERROR))?;

    let max_fee_per_gas =
        get_max_fee_per_gas_from_opt_param(max_fee_per_gas_param, client.evm_network())
            .map_err(|err| (err, FEES_ERROR))?;
    wallet.set_transaction_config(TransactionConfig { max_fee_per_gas });

    println!("🌳 Using Merkle batch payment");

    let event_receiver = client.enable_client_events();
    let (upload_summary_thread, upload_completed_tx) = collect_upload_summary(event_receiver);

    println!("Uploading data to network...");
    info!(
        "Uploading {} file: {file}",
        if public { "public" } else { "private" }
    );

    let dir_path = PathBuf::from(file);
    let name = dir_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or(file.to_string());

    // upload dir
    let not_single_file = !dir_path.is_file();
    let (archive_addr, local_addr) =
        match upload_dir(&client, &wallet, dir_path.clone(), public, no_archive).await {
            Ok((a, l)) => (a, l),
            Err(err) => {
                let exit_code = upload_exit_code(&err);
                return Err((
                    eyre!(err).wrap_err("Failed to upload file".to_string()),
                    exit_code,
                ));
            }
        };

    // wait for upload to complete
    if let Err(e) = upload_completed_tx.send(()) {
        error!("Failed to send upload completed event: {e:?}");
        eprintln!("Failed to send upload completed event: {e:?}");
    }

    // get summary
    let summary = upload_summary_thread
        .await
        .map_err(|err| (eyre!(err), IO_ERROR))?;
    if summary.records_paid == 0 {
        println!("All chunks already exist on the network.");
    } else {
        println!("Successfully uploaded: {file}");
        println!("At address: {local_addr}");
        info!("Successfully uploaded: {file} at address: {local_addr}");
        println!("Number of chunks uploaded: {}", summary.records_paid);
        println!(
            "Number of chunks already paid/uploaded: {}",
            summary.records_already_paid
        );
        println!("Total cost: {} AttoTokens", summary.tokens_spent);
    }
    info!("Summary for upload of file {file} at {local_addr:?}: {summary:?}");

    // save archive to local user data
    if !no_archive && not_single_file {
        let writer = if public {
            crate::user_data::write_local_public_file_archive(archive_addr.clone(), &name)
        } else {
            crate::user_data::write_local_private_file_archive(
                archive_addr.clone(),
                local_addr.clone(),
                &name,
            )
        };
        writer
            .wrap_err("Failed to save file to local user data")
            .with_suggestion(|| "Local user data saves the file address above to disk, without it you need to keep track of the address yourself")
            .map_err(|err| (err, IO_ERROR))?;
        info!("Saved file to local user data");
    }

    // save single private files to local user data
    if !not_single_file && !public {
        let writer = crate::user_data::write_local_private_file(
            archive_addr.clone(),
            local_addr.clone(),
            &name,
        );
        writer
            .wrap_err("Failed to save private file to local user data")
            .with_suggestion(|| "Local user data saves the file address above to disk, without it you need to keep track of the address yourself")
            .map_err(|err| (err, IO_ERROR))?;
        info!("Saved private file to local user data");
    }

    // save single public files to local user data
    if !not_single_file && public {
        let writer = crate::user_data::write_local_public_file(local_addr.to_owned(), &name);
        writer
            .wrap_err("Failed to save public file to local user data")
            .with_suggestion(|| "Local user data saves the file address above to disk, without it you need to keep track of the address yourself")
            .map_err(|err| (err, IO_ERROR))?;
        info!("Saved public file to local user data");
    }

    Ok(())
}

/// Uploads a file or directory to the network using Merkle batch payment.
/// Single files are uploaded without an archive, directories are uploaded with an archive.
/// The no_archive argument can be used to skip the archive upload.
/// Returns the archive address if any and the address to access the data.
async fn upload_dir(
    client: &Client,
    wallet: &autonomi::Wallet,
    dir_path: PathBuf,
    public: bool,
    no_archive: bool,
) -> Result<(String, String), UploadError> {
    use autonomi::client::data::DataAddress;
    use autonomi::client::files::{PrivateArchive, PublicArchive};

    let is_single_file = dir_path.is_file();

    // Try to load cached receipt, otherwise use wallet
    let path_str = dir_path.to_string_lossy().to_string();
    let payment_option =
        match cached_payments::load_merkle_payment_for_file(&path_str).map_err(|e| {
            UploadError::PutError(autonomi::client::PutError::Serialization(format!(
                "Failed to load cached payment: {e}"
            )))
        })? {
            Some(receipt) => {
                println!("Using cached Merkle payment for {path_str}");
                MerklePaymentOption::Receipt(receipt)
            }
            None => MerklePaymentOption::Wallet(wallet),
        };

    // Upload files with Merkle payment
    let results = client
        .files_put_with_merkle_payment(dir_path.clone(), public, payment_option)
        .await
        .map_err(|e| {
            // If upload failed but payment succeeded, save the receipt for retry
            if let MerkleFilePutError::Upload { ref receipt, .. } = e {
                let path_str = dir_path.to_string_lossy().to_string();
                let res = cached_payments::save_merkle_payment(&path_str, receipt);
                println!("Cached Merkle payment to local disk for {path_str}: {res:?}");
            }
            UploadError::PutError(autonomi::client::PutError::Serialization(format!(
                "Merkle payment error: {e}"
            )))
        })?;

    // Create payment option for archive uploads
    let payment_option = PaymentOption::Wallet(wallet.clone());

    if public {
        // Build PublicArchive from results
        let mut public_archive = PublicArchive::new();
        let mut addrs = vec![];

        for (relative_path, datamap, metadata) in results {
            // Convert DataMapChunk to DataAddress
            let data_address = DataAddress::new(*datamap.0.name());
            println!("  - {relative_path:?}: {:?}", data_address.to_hex());
            addrs.push(data_address.to_hex());
            public_archive.add_file(relative_path, data_address, metadata);
        }

        if no_archive || is_single_file {
            if addrs.len() > MAX_ADDRESSES_TO_PRINT {
                Ok(("no-archive".to_string(), "multiple addresses".to_string()))
            } else {
                Ok(("no-archive".to_string(), addrs.join(", ")))
            }
        } else {
            let (_, addr) = client
                .archive_put_public(&public_archive, payment_option)
                .await?;
            Ok((addr.to_hex(), addr.to_hex()))
        }
    } else {
        // Build PrivateArchive from results
        let mut private_archive = PrivateArchive::new();
        let mut addrs = vec![];

        for (relative_path, datamap, metadata) in results {
            println!("  - {relative_path:?}: {:?}", datamap.to_hex());
            addrs.push(datamap.to_hex());
            private_archive.add_file(relative_path, datamap, metadata);
        }

        if no_archive || is_single_file {
            if addrs.len() > MAX_ADDRESSES_TO_PRINT {
                Ok(("no-archive".to_string(), "multiple addresses".to_string()))
            } else if is_single_file && addrs.len() == 1 {
                // For single private files, return both full hex and short address
                if let Some((_, private_datamap, _)) = private_archive.iter().next() {
                    Ok((private_datamap.to_hex(), private_datamap.address()))
                } else {
                    Ok(("no-archive".to_string(), addrs.join(", ")))
                }
            } else {
                Ok(("no-archive".to_string(), addrs.join(", ")))
            }
        } else {
            let (_, private_datamap) = client.archive_put(&private_archive, payment_option).await?;
            Ok((private_datamap.to_hex(), private_datamap.address()))
        }
    }
}

pub async fn download(
    addr: &str,
    dest_path: &str,
    network_context: NetworkContext,
    quorum: Option<Quorum>,
    retries: Option<usize>,
    cache_chunks: bool,
    cache_dir: Option<&PathBuf>,
) -> Result<(), ExitCodeError> {
    let mut config = ClientOperatingStrategy::new();

    if let Some(quorum) = quorum {
        config.chunks.get_quorum = quorum;
    }

    if let Some(retries) = retries {
        config.chunks.get_retry = RetryStrategy::N(retries);
    }

    // Enable chunk caching in config (enabled by default unless disabled)
    if cache_chunks {
        config.chunk_cache_enabled = true;
        config.chunk_cache_dir = cache_dir.cloned();
        // Only print message if custom cache dir is specified
        if let Some(dir) = cache_dir {
            println!("Using custom cache directory: {}", dir.display());
        }
    } else {
        config.chunk_cache_enabled = false;
        println!("Chunk caching disabled");
    }

    let client = crate::actions::connect_to_network_with_config(network_context, config).await?;

    crate::actions::download(addr, dest_path, &client).await
}

pub async fn list(network_context: NetworkContext, verbose: bool) -> Result<(), ExitCodeError> {
    let mut config = ClientOperatingStrategy::new();
    config.chunks.get_quorum = Quorum::One;
    config.chunks.get_retry = RetryStrategy::None;

    let maybe_client = if verbose {
        match crate::actions::connect_to_network_with_config(network_context, config).await {
            Ok(client) => Some(client),
            Err((mut err, code)) => {
                err = err.with_suggestion(|| "Try running without --verbose, -v");
                return Err((err, code));
            }
        }
    } else {
        None
    };

    // get public file archives
    println!("Retrieving local user data...");
    let file_archives = crate::user_data::get_local_public_file_archives()
        .wrap_err("Failed to get local public file archives")
        .map_err(|err| (err, IO_ERROR))?;

    println!(
        "✅ You have {} public file archive(s):",
        file_archives.len()
    );
    for (addr, name) in file_archives {
        println!("{}: {}", name, addr.to_hex());
        if let (true, Some(client)) = (verbose, maybe_client.as_ref()) {
            if let Ok(Analysis::PublicArchive { archive, .. }) =
                client.analyze_address(&addr.to_string(), false).await
            {
                for (file_path, data_addr, _meta) in archive.iter() {
                    println!("  - {file_path:?}: {data_addr:?}");
                }
            } else {
                println!("  - Not found on network");
            }
        }
    }

    // get public files
    println!();
    let public_files = crate::user_data::get_local_public_files()
        .wrap_err("Failed to get local public files")
        .map_err(|err| (err, IO_ERROR))?;

    println!("✅ You have {} public file(s):", public_files.len());
    for (addr, name) in public_files {
        println!("{}: {}", name, addr.to_hex());
        if let (true, Some(client)) = (verbose, maybe_client.as_ref()) {
            if let Ok(file_bytes) = client.data_get_public(&addr).await {
                println!("  - File size: {} bytes", file_bytes.len());
            } else {
                println!("  - Not found on network");
            }
        }
    }

    // get private file archives
    println!();
    let private_file_archives = crate::user_data::get_local_private_file_archives()
        .wrap_err("Failed to get local private file archives")
        .map_err(|err| (err, IO_ERROR))?;

    println!(
        "✅ You have {} private file archive(s):",
        private_file_archives.len()
    );
    for (addr, name) in private_file_archives {
        println!("{}: {}", name, addr.address());
        if let (true, Some(client)) = (verbose, maybe_client.as_ref()) {
            if let Ok(Analysis::PrivateArchive(private_archive)) =
                client.analyze_address(&addr.to_string(), false).await
            {
                for (file_path, _data_addr, _meta) in private_archive.iter() {
                    println!("  - {file_path:?}");
                }
            } else {
                println!("  - Not found on network");
            }
        }
    }

    // get private files
    println!();
    let private_files = crate::user_data::get_local_private_files()
        .wrap_err("Failed to get local private files")
        .map_err(|err| (err, IO_ERROR))?;

    println!("✅ You have {} private file(s):", private_files.len());
    for (addr, name) in private_files {
        println!("{}: {}", name, addr.address());
        if let (true, Some(client)) = (verbose, maybe_client.as_ref()) {
            if let Ok(file_bytes) = client.data_get(&addr).await {
                println!("  - File size: {} bytes", file_bytes.len());
            } else {
                println!("  - Not found on network");
            }
        }
    }

    println!();
    println!(
        "> Note that private data addresses are not network addresses, they are only used for referring to private data client side."
    );
    Ok(())
}
