// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ANT_PEERS_ENV;
use crate::BootstrapCacheStore;
use crate::BootstrapConfig;
use crate::ContactsFetcher;
use crate::Result;
use crate::contacts_fetcher::ALPHANET_CONTACTS;
use crate::contacts_fetcher::MAINNET_CONTACTS;
use crate::craft_valid_multiaddr;
use crate::craft_valid_multiaddr_from_str;
use crate::error::Error;
use crate::multiaddr_get_peer_id;
use ant_protocol::version::ALPHANET_ID;
use ant_protocol::version::MAINNET_ID;
use ant_protocol::version::get_network_id;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    core::connection::ConnectedPoint,
    multiaddr::Protocol,
    swarm::{
        DialError, NetworkBehaviour,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use rand::seq::SliceRandom;
use std::collections::{HashSet, VecDeque};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use url::Url;

/// The max number of concurrent dials to be made during the initial bootstrap process.
const CONCURRENT_DIALS: usize = 3;
/// The max number of peers to be added before stopping the initial bootstrap process.
const MAX_PEERS_BEFORE_TERMINATION: usize = 5;

/// Manages the flow of obtaining bootstrap peer addresses from various sources and also writes to the bootstrap cache.
///
/// The sources are tried in the following order while reading:
/// 1. Environment variable `ANT_PEERS`
/// 2. Command-line provided addresses
/// 3. Bootstrap cache file on disk
/// 4. Network contacts endpoints
///
/// Addresses are returned one at a time via the `next_addr` method.
/// It handles asynchronous fetching from the cache and contacts endpoints,
/// ensuring only one fetch is in progress at a time.
///
/// If no more addresses are available from any source, `next_addr` returns an error.
/// It is expected that the caller will retry `next_addr` later to allow
/// for asynchronous fetches to complete.
#[derive(Debug)]
pub struct Bootstrap {
    cache_store: BootstrapCacheStore,
    addrs: VecDeque<Multiaddr>,
    // fetcher
    cache_pending: bool,
    contacts_progress: Option<ContactsProgress>,
    event_tx: UnboundedSender<FetchEvent>,
    event_rx: UnboundedReceiver<FetchEvent>,
    fetch_in_progress: Option<FetchKind>,
    // dialer
    ongoing_dials: HashSet<Multiaddr>,
    bootstrap_peer_ids: HashSet<PeerId>,
    bootstrap_completed: bool,
}

impl Bootstrap {
    pub async fn new(mut config: BootstrapConfig) -> Result<Self> {
        let contacts_progress = Self::build_contacts_progress(&config)?;

        let mut addrs_queue = VecDeque::new();
        let mut bootstrap_peer_ids = HashSet::new();
        if !config.first {
            for addr in Self::fetch_from_env() {
                Self::push_addr(&mut addrs_queue, &mut bootstrap_peer_ids, addr);
            }

            for addr in config.initial_peers.drain(..) {
                if let Some(addr) = craft_valid_multiaddr(&addr, false) {
                    info!("Adding addr from arguments: {addr}");
                    Self::push_addr(&mut addrs_queue, &mut bootstrap_peer_ids, addr);
                } else {
                    warn!("Invalid multiaddress format from arguments: {addr}");
                }
            }
        }
        Self::shuffle_addrs(&mut addrs_queue);

        let cache_pending = !config.first && !config.disable_cache_reading;
        if !cache_pending {
            info!("Not loading from cache as per configuration");
        }
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();

        let cache_store = BootstrapCacheStore::new(config.clone())?;
        if config.first {
            info!("First node in network; clearing any existing cache");
            cache_store.write().await?;
        }
        info!("Cache store is initialized and will sync and flush periodically");
        cache_store.sync_and_flush_periodically();

        Ok(Self {
            cache_store,
            addrs: addrs_queue,
            cache_pending,
            contacts_progress,
            event_tx,
            event_rx,
            fetch_in_progress: None,
            ongoing_dials: HashSet::new(),
            bootstrap_peer_ids,
            bootstrap_completed: config.first,
        })
    }

    /// Returns the next address to try for bootstrapping.
    /// None if a fetch is in progress and no address is ready yet.
    /// Error if there are no more addresses to try.
    fn next_addr(&mut self) -> Result<Option<Multiaddr>> {
        loop {
            self.process_events();

            if let Some(addr) = self.addrs.pop_front() {
                info!(?addr, "next_addr returning queued address");
                return Ok(Some(addr));
            }

            if self.fetch_in_progress.is_some() {
                info!("next_addr waiting for in-flight fetch result");
                return Ok(None);
            }

            if self.cache_pending && !matches!(self.fetch_in_progress, Some(FetchKind::Cache)) {
                info!("next_addr triggering cache fetch");
                self.start_cache_fetch()?;
                continue;
            }

            if self.contacts_progress.is_some()
                && !matches!(self.fetch_in_progress, Some(FetchKind::Contacts))
            {
                info!("next_addr triggering contacts fetch");
                self.start_contacts_fetch()?;
                if self.fetch_in_progress.is_some() {
                    return Ok(None);
                }
                continue;
            }

            info!("next_addr exhausted all address sources");
            return Err(Error::NoBootstrapPeersFound);
        }
    }

    fn process_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                FetchEvent::Cache(addrs) => {
                    info!(count = addrs.len(), "process_events received cache batch");
                    if addrs.is_empty() {
                        info!("No addresses retrieved from cache");
                    } else {
                        self.extend_with_addrs(addrs);
                    }
                }
                FetchEvent::Contacts(addrs) => {
                    info!(
                        count = addrs.len(),
                        "process_events received contacts batch"
                    );
                    if !addrs.is_empty() {
                        self.extend_with_addrs(addrs);
                    }
                    if self
                        .contacts_progress
                        .as_ref()
                        .is_none_or(ContactsProgress::is_empty)
                    {
                        self.contacts_progress = None;
                    }
                }
            }

            self.fetch_in_progress = None;
        }
    }

    fn extend_with_addrs(&mut self, addrs: Vec<Multiaddr>) {
        if addrs.is_empty() {
            return;
        }
        for addr in addrs {
            Self::push_addr(&mut self.addrs, &mut self.bootstrap_peer_ids, addr);
        }
        Self::shuffle_addrs(&mut self.addrs);
    }

    fn push_addr(queue: &mut VecDeque<Multiaddr>, peer_ids: &mut HashSet<PeerId>, addr: Multiaddr) {
        if let Some(peer_id) = multiaddr_get_peer_id(&addr) {
            peer_ids.insert(peer_id);
        }
        queue.push_back(addr);
    }

    fn shuffle_addrs(queue: &mut VecDeque<Multiaddr>) {
        let mut tmp: Vec<Multiaddr> = queue.drain(..).collect();
        let mut rng = rand::thread_rng();
        tmp.shuffle(&mut rng);
        queue.extend(tmp);
    }

    fn pop_p2p(addr: &mut Multiaddr) -> Option<PeerId> {
        if let Some(Protocol::P2p(peer_id)) = addr.iter().last() {
            let _ = addr.pop();
            Some(peer_id)
        } else {
            None
        }
    }

    fn try_next_dial_addr(&mut self) -> Result<Option<Multiaddr>> {
        match self.next_addr() {
            Ok(Some(addr)) => Ok(Some(addr)),
            Ok(None) => Ok(None),
            Err(Error::NoBootstrapPeersFound) => {
                self.bootstrap_completed = true;
                Err(Error::NoBootstrapPeersFound)
            }
            Err(err) => Err(err),
        }
    }

    fn should_continue_bootstrapping(&mut self, peers_in_rt: usize, verbose: bool) -> bool {
        if self.bootstrap_completed {
            if verbose {
                info!("Initial bootstrap process has already completed successfully.");
            } else {
                trace!("Initial bootstrap process has already completed successfully.");
            }
            return false;
        }

        if peers_in_rt >= MAX_PEERS_BEFORE_TERMINATION {
            self.bootstrap_completed = true;
            self.addrs.clear();
            self.ongoing_dials.clear();

            if verbose {
                info!(
                    "Initial bootstrap process completed successfully. We have {peers_in_rt} peers in the routing table."
                );
            } else {
                trace!(
                    "Initial bootstrap process completed successfully. We have {peers_in_rt} peers in the routing table."
                );
            }
            return false;
        }

        if self.ongoing_dials.len() >= CONCURRENT_DIALS {
            if verbose {
                info!(
                    "Initial bootstrap has {} ongoing dials. Not dialing anymore.",
                    self.ongoing_dials.len()
                );
            } else {
                debug!(
                    "Initial bootstrap has {} ongoing dials. Not dialing anymore.",
                    self.ongoing_dials.len()
                );
            }
            return false;
        }

        if self.addrs.is_empty() {
            if self.cache_pending
                || self.contacts_progress.is_some()
                || self.fetch_in_progress.is_some()
            {
                if verbose {
                    info!("Initial bootstrap is awaiting additional addresses to arrive.");
                } else {
                    debug!("Initial bootstrap is awaiting additional addresses to arrive.");
                }
                return false;
            }

            if verbose {
                info!(
                    "We have {peers_in_rt} peers in RT, but no more addresses to dial. Stopping initial bootstrap."
                );
            } else {
                debug!(
                    "We have {peers_in_rt} peers in RT, but no more addresses to dial. Stopping initial bootstrap."
                );
            }

            self.bootstrap_completed = true;
            return false;
        }

        true
    }

    fn handle_successful_connection<B: NetworkBehaviour>(
        &mut self,
        peer_id: &PeerId,
        endpoint: &ConnectedPoint,
        swarm: &mut Swarm<B>,
        peers_in_rt: usize,
    ) {
        if self.bootstrap_completed {
            return;
        }

        if let ConnectedPoint::Dialer { address, .. } = endpoint
            && !self.ongoing_dials.remove(address)
        {
            self.ongoing_dials
                .retain(|addr| match multiaddr_get_peer_id(addr) {
                    Some(id) => id != *peer_id,
                    None => true,
                });
        }

        self.trigger_bootstrapping_process_internal(swarm, peers_in_rt, false);
    }

    fn trigger_bootstrapping_process_internal<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        peers_in_rt: usize,
        verbose: bool,
    ) {
        if !self.should_continue_bootstrapping(peers_in_rt, verbose) {
            return;
        }

        while self.ongoing_dials.len() < CONCURRENT_DIALS {
            match self.try_next_dial_addr() {
                Ok(Some(mut addr)) => {
                    let addr_clone = addr.clone();
                    let peer_id = Self::pop_p2p(&mut addr);

                    let opts = match peer_id {
                        Some(peer_id) => DialOpts::peer_id(peer_id)
                            .condition(PeerCondition::NotDialing)
                            .addresses(vec![addr])
                            .build(),
                        None => DialOpts::unknown_peer_id().address(addr).build(),
                    };

                    info!("Trying to dial peer with address: {addr_clone}");

                    match swarm.dial(opts) {
                        Ok(()) => {
                            info!(
                                "Dial attempt initiated for peer with address: {addr_clone}. Ongoing dial attempts: {}",
                                self.ongoing_dials.len() + 1
                            );
                            let _ = self.ongoing_dials.insert(addr_clone);
                        }
                        Err(err) => match err {
                            DialError::LocalPeerId { .. } => {
                                warn!(
                                    "Failed to dial peer with address: {addr_clone}. This is our own peer ID. Dialing the next peer"
                                );
                            }
                            DialError::NoAddresses => {
                                error!(
                                    "Failed to dial peer with address: {addr_clone}. No addresses found. Dialing the next peer"
                                );
                            }
                            DialError::DialPeerConditionFalse(_) => {
                                warn!(
                                    "We are already dialing the peer with address: {addr_clone}. Dialing the next peer. This error is harmless."
                                );
                            }
                            DialError::Aborted => {
                                error!(
                                    "Pending connection attempt has been aborted for {addr_clone}. Dialing the next peer."
                                );
                            }
                            DialError::WrongPeerId { obtained, .. } => {
                                error!(
                                    "The peer identity obtained on the connection did not match the one that was expected. Obtained: {obtained}. Dialing the next peer."
                                );
                            }
                            DialError::Denied { cause } => {
                                error!(
                                    "The dialing attempt was denied by the remote peer. Cause: {cause}. Dialing the next peer."
                                );
                            }
                            DialError::Transport(items) => {
                                error!(
                                    "Failed to dial peer with address: {addr_clone}. Transport error: {items:?}. Dialing the next peer."
                                );
                            }
                        },
                    }
                }
                Ok(None) => {
                    debug!("Waiting for additional bootstrap addresses before continuing to dial");
                    break;
                }
                Err(Error::NoBootstrapPeersFound) => {
                    info!("No more bootstrap peers available to dial.");
                    break;
                }
                Err(err) => {
                    warn!("Failed to obtain next bootstrap address: {err}");
                    break;
                }
            }
        }
    }

    pub fn trigger_bootstrapping_process<B: NetworkBehaviour>(
        &mut self,
        swarm: &mut Swarm<B>,
        peers_in_rt: usize,
    ) {
        self.trigger_bootstrapping_process_internal(swarm, peers_in_rt, true);
    }

    pub fn on_connection_established<B: NetworkBehaviour>(
        &mut self,
        peer_id: &PeerId,
        endpoint: &ConnectedPoint,
        swarm: &mut Swarm<B>,
        peers_in_rt: usize,
    ) {
        self.handle_successful_connection(peer_id, endpoint, swarm, peers_in_rt);
    }

    pub fn on_outgoing_connection_error<B: NetworkBehaviour>(
        &mut self,
        peer_id: Option<PeerId>,
        swarm: &mut Swarm<B>,
        peers_in_rt: usize,
    ) {
        if self.bootstrap_completed {
            return;
        }

        match peer_id {
            Some(peer_id) => {
                self.ongoing_dials.retain(|addr| {
                    if let Some(id) = multiaddr_get_peer_id(addr) {
                        id != peer_id
                    } else {
                        true
                    }
                });
            }
            None => {
                self.ongoing_dials
                    .retain(|addr| multiaddr_get_peer_id(addr).is_some());
            }
        }

        self.trigger_bootstrapping_process_internal(swarm, peers_in_rt, false);
    }

    pub fn is_bootstrap_peer(&self, peer_id: &PeerId) -> bool {
        self.bootstrap_peer_ids.contains(peer_id)
    }

    pub fn has_terminated(&self) -> bool {
        self.bootstrap_completed
    }

    #[cfg(test)]
    pub(crate) fn next_addr_for_tests(&mut self) -> Result<Option<Multiaddr>> {
        self.next_addr()
    }

    fn start_cache_fetch(&mut self) -> Result<()> {
        if matches!(self.fetch_in_progress, Some(FetchKind::Cache)) {
            error!("Cache fetch already in progress, not starting another");
            return Ok(());
        }

        self.cache_pending = false;
        let config = self.cache_store.config().clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let addrs = match tokio::task::spawn_blocking(move || {
                BootstrapCacheStore::load_cache_data(&config)
            })
            .await
            {
                Ok(Ok(cache_data)) => cache_data.get_all_addrs().cloned().collect(),
                Ok(Err(err)) => {
                    warn!("Failed to load cache data: {err}");
                    Vec::new()
                }
                Err(err) => {
                    warn!("Cache fetch task failed to join: {err}");
                    Vec::new()
                }
            };

            info!(
                "Bootstrap cache loaded from disk with {} addresses",
                addrs.len()
            );
            let _ = event_tx.send(FetchEvent::Cache(addrs));
        });

        self.fetch_in_progress = Some(FetchKind::Cache);

        Ok(())
    }

    fn start_contacts_fetch(&mut self) -> Result<()> {
        if matches!(self.fetch_in_progress, Some(FetchKind::Contacts)) {
            error!("Contacts fetch already in progress, not starting another");
            return Ok(());
        }

        let Some(progress) = self.contacts_progress.as_mut() else {
            info!("No contacts progress available");
            return Ok(());
        };

        let Some(endpoint) = progress.next_endpoint() else {
            info!("No more contacts endpoints to try");
            self.contacts_progress = None;
            return Ok(());
        };

        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let Ok(fetcher) = ContactsFetcher::with_endpoints(vec![endpoint.clone()]) else {
                warn!("Failed to create contacts fetcher for {endpoint}");
                let _ = event_tx.send(FetchEvent::Contacts(Vec::new()));
                return;
            };

            let addrs = match fetcher.fetch_bootstrap_addresses().await {
                Ok(addrs) => addrs,
                Err(err) => {
                    warn!("Failed to fetch contacts from {endpoint}: {err}");
                    Vec::new()
                }
            };

            info!(
                "Contacts fetch completed from endpoint {endpoint:?} with {} addresses",
                addrs.len()
            );
            let _ = event_tx.send(FetchEvent::Contacts(addrs));
        });

        self.fetch_in_progress = Some(FetchKind::Contacts);

        Ok(())
    }

    fn build_contacts_progress(config: &BootstrapConfig) -> Result<Option<ContactsProgress>> {
        if config.first {
            info!("First node in network; not fetching contacts");
            return Ok(None);
        }

        if config.local {
            info!("Local network configuration; skipping contacts endpoints");
            return Ok(None);
        }

        if !config.network_contacts_url.is_empty() {
            let endpoints = config
                .network_contacts_url
                .iter()
                .map(|endpoint| endpoint.parse::<Url>().map_err(|_| Error::FailedToParseUrl))
                .collect::<Result<Vec<_>>>()?;
            info!("Using provided contacts endpoints: {endpoints:?}");
            return Ok(ContactsProgress::new(endpoints));
        }

        match get_network_id() {
            id if id == MAINNET_ID => {
                info!("Using built-in mainnet contacts endpoints");
                Ok(ContactsProgress::from_static(MAINNET_CONTACTS))
            }

            id if id == ALPHANET_ID => {
                info!("Using built-in alphanet contacts endpoints");
                Ok(ContactsProgress::from_static(ALPHANET_CONTACTS))
            }
            _ => Ok(None),
        }
    }

    pub fn fetch_from_env() -> Vec<Multiaddr> {
        let mut bootstrap_addresses = Vec::new();
        // Read from ANT_PEERS environment variable if present
        if let Ok(addrs) = std::env::var(ANT_PEERS_ENV) {
            for addr_str in addrs.split(',') {
                if let Some(addr) = craft_valid_multiaddr_from_str(addr_str, false) {
                    info!("Adding addr from environment variable: {addr}");
                    bootstrap_addresses.push(addr);
                } else {
                    warn!("Invalid multiaddress format from environment variable: {addr_str}");
                }
            }
        }
        bootstrap_addresses
    }

    pub fn cache_store_mut(&mut self) -> &mut BootstrapCacheStore {
        &mut self.cache_store
    }

    pub fn cache_store(&self) -> &BootstrapCacheStore {
        &self.cache_store
    }
}

#[derive(Debug)]
struct ContactsProgress {
    remaining: VecDeque<Url>,
}

enum FetchEvent {
    Cache(Vec<Multiaddr>),
    Contacts(Vec<Multiaddr>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FetchKind {
    Cache,
    Contacts,
}

impl ContactsProgress {
    fn new(urls: Vec<Url>) -> Option<Self> {
        if urls.is_empty() {
            None
        } else {
            Some(Self {
                remaining: VecDeque::from(urls),
            })
        }
    }

    fn from_static(urls: &[&str]) -> Option<Self> {
        let mut parsed = Vec::new();
        for url in urls {
            match url.parse::<Url>() {
                Ok(parsed_url) => parsed.push(parsed_url),
                Err(err) => {
                    warn!("Failed to parse static contacts URL {url}: {err}");
                }
            }
        }
        Self::new(parsed)
    }

    fn next_endpoint(&mut self) -> Option<Url> {
        self.remaining.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InitialPeersConfig,
        cache_store::{BootstrapCacheStore, cache_data_v1::CacheData},
        multiaddr_get_peer_id,
    };
    use libp2p::Multiaddr;
    use std::collections::HashSet;
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;
    use tokio::sync::{Mutex, OwnedMutexGuard};
    use tokio::time::sleep;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    async fn env_lock() -> OwnedMutexGuard<()> {
        static ENV_MUTEX: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
        Arc::clone(ENV_MUTEX.get_or_init(|| Arc::new(Mutex::new(()))))
            .lock_owned()
            .await
    }

    #[allow(unsafe_code)]
    fn set_env_var(key: &str, value: &str) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    #[allow(unsafe_code)]
    fn remove_env_var(key: &str) {
        unsafe {
            std::env::remove_var(key);
        }
    }

    async fn expect_next_addr(flow: &mut Bootstrap) -> Result<Multiaddr> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match flow.next_addr_for_tests() {
                Ok(Some(addr)) => return Ok(addr),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        panic!("Timed out waiting for next address");
                    }
                    sleep(Duration::from_millis(5)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn expect_err(flow: &mut Bootstrap) -> Error {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match flow.next_addr_for_tests() {
                Ok(Some(addr)) => panic!("unexpected address returned: {addr}"),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        panic!("Timed out waiting for error from flow");
                    }
                    sleep(Duration::from_millis(5)).await;
                }
                Err(err) => return err,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_cli_arguments_precedence() {
        let env_addr: Multiaddr =
            "/ip4/10.0.0.1/tcp/1200/p2p/12D3KooWQnE7zXkVUEGBnJtNfR88Ujz4ezgm6bVnkvxHCzhF7S5S"
                .parse()
                .unwrap();
        let cli_addr: Multiaddr =
            "/ip4/10.0.0.2/tcp/1201/p2p/12D3KooWQx2TSK7g1C8x3QK7gBqdqbQEkd6vDT7Pxu5gb1xmgjvp"
                .parse()
                .unwrap();

        let _env_guard = env_lock().await;
        set_env_var(ANT_PEERS_ENV, &env_addr.to_string());

        let temp_dir = TempDir::new().unwrap();

        let config = InitialPeersConfig {
            ignore_cache: true,
            local: true,
            bootstrap_cache_dir: Some(temp_dir.path().to_path_buf()),
            addrs: vec![cli_addr.clone()],
            ..Default::default()
        };
        let config = BootstrapConfig::try_from(&config).expect("Failed to create BootstrapConfig");
        let mut flow = Bootstrap::new(config).await.unwrap();

        let first_two = vec![
            expect_next_addr(&mut flow).await.unwrap(),
            expect_next_addr(&mut flow).await.unwrap(),
        ];
        let first_set: HashSet<_> = first_two.into_iter().collect();
        let expected: HashSet<_> = [env_addr.clone(), cli_addr.clone()].into_iter().collect();
        assert_eq!(first_set, expected);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));

        remove_env_var(ANT_PEERS_ENV);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_env_variable_parsing() {
        let _env_guard = env_lock().await;
        set_env_var(
            ANT_PEERS_ENV,
            "/ip4/127.0.0.1/udp/8080/quic-v1/p2p/12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhgFRcw3UERE,\
/ip4/127.0.0.2/udp/8081/quic-v1/p2p/12D3KooWD2aV1f3qkhggzEFaJ24CEFYkSdZF5RKoMLpU6CwExYV5",
        );

        let parsed = Bootstrap::fetch_from_env();
        remove_env_var(ANT_PEERS_ENV);

        assert_eq!(parsed.len(), 2);
        let parsed_set: std::collections::HashSet<_> =
            parsed.into_iter().map(|addr| addr.to_string()).collect();
        let expected = std::collections::HashSet::from([
            "/ip4/127.0.0.1/udp/8080/quic-v1/p2p/12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhgFRcw3UERE"
                .to_string(),
            "/ip4/127.0.0.2/udp/8081/quic-v1/p2p/12D3KooWD2aV1f3qkhggzEFaJ24CEFYkSdZF5RKoMLpU6CwExYV5"
                .to_string(),
        ]);
        assert_eq!(parsed_set, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn loads_addresses_from_cache_when_initial_queue_is_empty() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);
        let cache_addr: Multiaddr =
            "/ip4/127.0.0.1/tcp/1202/p2p/12D3KooWKGt8umjJQ4sDzFXo2UcHBaF33rqmFcWtXM6nbryL5G4J"
                .parse()
                .unwrap();
        let peer_id = multiaddr_get_peer_id(&cache_addr).unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_name = BootstrapCacheStore::cache_file_name(true);

        let mut cache_data = CacheData::default();
        cache_data.add_peer(peer_id, std::iter::once(&cache_addr), 3, 10);
        cache_data
            .write_to_file(temp_dir.path(), &file_name)
            .unwrap();

        let config = InitialPeersConfig {
            local: true,
            bootstrap_cache_dir: Some(temp_dir.path().to_path_buf()),
            ..Default::default()
        };
        let config = BootstrapConfig::try_from(&config).expect("Failed to create BootstrapConfig");
        let mut flow = Bootstrap::new(config).await.unwrap();

        let got = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(got, cache_addr);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_first_flag_behavior() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/peers"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "/ip4/127.0.0.1/udp/8080/quic-v1/p2p/12D3KooWRBhwfeP2Y4TCx1SM6s9rUoHhR5STiGwxBhgFRcw3UERE",
            ))
            .expect(0)
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let config = InitialPeersConfig {
                first: true,
                addrs: vec![
                "/ip4/127.0.0.2/udp/8081/quic-v1/p2p/12D3KooWD2aV1f3qkhggzEFaJ24CEFYkSdZF5RKoMLpU6CwExYV5"
                    .parse()
                    .unwrap(),
                ],
                network_contacts_url: vec![format!("{}/peers", mock_server.uri())],
                bootstrap_cache_dir: Some(temp_dir.path().to_path_buf()),
                ..Default::default()
            };
        let config = BootstrapConfig::try_from(&config).expect("Failed to create BootstrapConfig");
        let mut flow = Bootstrap::new(config).await.unwrap();

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));
        assert!(
            mock_server.received_requests().await.unwrap().is_empty(),
            "first flag should prevent contact fetches"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_multiple_network_contacts() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);

        let mock_server = MockServer::start().await;

        let contact_one: Multiaddr =
            "/ip4/192.168.0.1/tcp/1203/p2p/12D3KooWPULWT1qXJ1jzYVtQocvKXgcv6U7Pp3ui3EB7mN8hXAsP"
                .parse()
                .unwrap();
        let contact_two: Multiaddr =
            "/ip4/192.168.0.2/tcp/1204/p2p/12D3KooWPsMPaEjaWjW6GWpAne6LYcwBQEJfnDbhQFNs6ytzmBn5"
                .parse()
                .unwrap();

        Mock::given(method("GET"))
            .and(path("/first"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_one.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/second"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_two.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = InitialPeersConfig {
            ignore_cache: true,
            network_contacts_url: vec![
                format!("{}/first", mock_server.uri()),
                format!("{}/second", mock_server.uri()),
            ],
            ..Default::default()
        };
        let config = BootstrapConfig::try_from(&config).expect("Failed to create BootstrapConfig");
        let mut flow = Bootstrap::new(config).await.unwrap();

        let first = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(first, contact_one);

        let second = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(second, contact_two);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url.path(), "/first");
        assert_eq!(requests[1].url.path(), "/second");

        remove_env_var(ANT_PEERS_ENV);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_full_bootstrap_flow() {
        let _env_guard = env_lock().await;
        remove_env_var(ANT_PEERS_ENV);

        let env_addr: Multiaddr =
            "/ip4/10.1.0.1/tcp/1300/p2p/12D3KooWBbtXX6gY5xPD7NzNGGbj2428NJQ4HNvvBnSE5g4R7Pkf"
                .parse()
                .unwrap();
        let cli_addr: Multiaddr =
            "/ip4/10.1.0.2/tcp/1301/p2p/12D3KooWCRfYwq9c3PAXo5cTp3snq72Knqukcec4c9qT1AMyvMPd"
                .parse()
                .unwrap();
        set_env_var(ANT_PEERS_ENV, &env_addr.to_string());

        let cache_addr_one: Multiaddr =
            "/ip4/10.1.0.3/tcp/1302/p2p/12D3KooWMmKJcWUP9UqP4g1n3LH1htkvSUStn1aQGQxGc1dQcYxA"
                .parse()
                .unwrap();
        let cache_addr_two: Multiaddr =
            "/ip4/10.1.0.4/tcp/1303/p2p/12D3KooWA4b4T6Dz4RUtqnYDEBt3eGkqRykGGBqBP3ZiZsaAJ2jp"
                .parse()
                .unwrap();

        let temp_dir = TempDir::new().unwrap();
        let file_name = BootstrapCacheStore::cache_file_name(false);
        let mut cache_data = CacheData::default();
        cache_data.add_peer(
            multiaddr_get_peer_id(&cache_addr_one).unwrap(),
            std::iter::once(&cache_addr_one),
            3,
            10,
        );
        cache_data.add_peer(
            multiaddr_get_peer_id(&cache_addr_two).unwrap(),
            std::iter::once(&cache_addr_two),
            3,
            10,
        );
        cache_data
            .write_to_file(temp_dir.path(), &file_name)
            .unwrap();

        let mock_server = MockServer::start().await;
        let contact_one: Multiaddr =
            "/ip4/10.1.0.5/tcp/1304/p2p/12D3KooWQGyiCWkmKvgFVF1PsvBLnBxG29BAsoAhH4m6qjUpBAk1"
                .parse()
                .unwrap();
        let contact_two: Multiaddr =
            "/ip4/10.1.0.6/tcp/1305/p2p/12D3KooWGpMibW82dManEXZDV4SSQSSHqzTeWY5Avzkdx6yrosNG"
                .parse()
                .unwrap();

        Mock::given(method("GET"))
            .and(path("/contacts_one"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_one.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/contacts_two"))
            .respond_with(ResponseTemplate::new(200).set_body_string(contact_two.to_string()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let file_path = temp_dir.path().join(format!(
            "version_{}/{}",
            CacheData::CACHE_DATA_VERSION,
            file_name
        ));
        let contents = std::fs::read_to_string(&file_path).unwrap();
        assert!(contents.contains(&cache_addr_one.to_string()));
        assert!(contents.contains(&cache_addr_two.to_string()));

        assert_eq!(
            Bootstrap::fetch_from_env(),
            vec![env_addr.clone()],
            "environment variable should yield the configured address"
        );

        let config = InitialPeersConfig {
            addrs: vec![cli_addr.clone()],
            bootstrap_cache_dir: Some(temp_dir.path().to_path_buf()),
            network_contacts_url: vec![
                format!("{}/contacts_one", mock_server.uri()),
                format!("{}/contacts_two", mock_server.uri()),
            ],
            ..Default::default()
        };
        let config = BootstrapConfig::try_from(&config).expect("Failed to create BootstrapConfig");
        let mut flow = Bootstrap::new(config).await.unwrap();

        let initial_results = vec![
            expect_next_addr(&mut flow).await.unwrap(),
            expect_next_addr(&mut flow).await.unwrap(),
        ];
        let initial_set: HashSet<_> = initial_results.into_iter().collect();
        let expected_initial: HashSet<_> =
            [env_addr.clone(), cli_addr.clone()].into_iter().collect();
        assert_eq!(initial_set, expected_initial);

        let cache_results = vec![
            expect_next_addr(&mut flow).await.unwrap(),
            expect_next_addr(&mut flow).await.unwrap(),
        ];
        let cache_set: HashSet<_> = cache_results.into_iter().collect();
        let expected_cache: HashSet<_> = [cache_addr_one.clone(), cache_addr_two.clone()]
            .into_iter()
            .collect();
        assert_eq!(cache_set, expected_cache);

        let contact_first = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(contact_first, contact_one);

        let contact_second = expect_next_addr(&mut flow).await.unwrap();
        assert_eq!(contact_second, contact_two);

        let err = expect_err(&mut flow).await;
        assert!(matches!(err, Error::NoBootstrapPeersFound));

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url.path(), "/contacts_one");
        assert_eq!(requests[1].url.path(), "/contacts_two");

        remove_env_var(ANT_PEERS_ENV);
    }
}
