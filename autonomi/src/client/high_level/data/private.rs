// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::time::Instant;

use crate::client::payment::PaymentOption;
use crate::client::{GetError, PutError};
use crate::data::DataAddress;
use crate::AttoTokens;
use crate::{self_encryption::encrypt, Client};

pub use crate::client::data_types::chunk::DataMapChunk;
pub use crate::Bytes;

impl Client {
    /// Fetch a blob of (private) data from the network
    ///
    /// # Example
    ///
    /// ```no_run
    /// use autonomi::{Client, Bytes};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::init().await?;
    /// # let data_map = todo!();
    /// let data_fetched = client.data_get(&data_map).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn data_get(&self, data_map: &DataMapChunk) -> Result<Bytes, GetError> {
        info!(
            "Fetching private data from Data Map {:?}",
            data_map.0.address()
        );
        let data = self.fetch_from_data_map_chunk(data_map.0.value()).await?;

        debug!("Successfully fetched a blob of private data from the network");
        Ok(data)
    }

    /// Upload a piece of private data to the network. This data will be self-encrypted.
    /// The [`DataMapChunk`] is not uploaded to the network, keeping the data private.
    ///
    /// Returns the [`DataMapChunk`] containing the map to the encrypted chunks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use autonomi::{Client, Bytes};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = Client::init().await?;
    /// # let wallet = todo!();
    /// let data = Bytes::from("Hello, World");
    /// let (total_cost, data_map) = client.data_put(data, wallet).await?;
    /// let data_fetched = client.data_get(&data_map).await?;
    /// assert_eq!(data, data_fetched);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn data_put(
        &self,
        data: Bytes,
        payment_option: PaymentOption,
    ) -> Result<(AttoTokens, DataMapChunk), PutError> {
        let now = Instant::now();
        let (data_map_chunk, chunks) = encrypt(data)?;
        debug!("Encryption took: {:.2?}", now.elapsed());

        let data_address = DataAddress::new(*data_map_chunk.address().xorname());
        let combined_chunks = vec![(
            (format!("Private Data {data_address:?}"), Some(data_address)),
            chunks,
        )];

        // Note within the `pay_and_upload`, UploadSummary will be sent to cli via event_channel.
        self.pay_and_upload(payment_option, combined_chunks)
            .await
            .map(|total_cost| (total_cost, DataMapChunk(data_map_chunk)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::data_types::chunk::Chunk;

    #[test]
    fn test_hex() {
        let data_map = DataMapChunk(Chunk::new(Bytes::from_static(b"hello")));
        let hex = data_map.to_hex();
        let data_map2 = DataMapChunk::from_hex(&hex).expect("Failed to decode hex");
        assert_eq!(data_map, data_map2);
    }
}
