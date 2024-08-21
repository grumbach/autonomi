use std::fmt::{Display, Formatter, Result};

use serde::{Deserialize, Serialize};
use strum::EnumIter;

#[derive(Clone, Debug, Default, EnumIter, Eq, PartialEq)]
pub enum ConnectionMode {
    #[default]
    Automatic,
    HomeNetwork,
    UPnP,
    CustomPorts,
}

impl Display for ConnectionMode {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ConnectionMode::HomeNetwork => write!(f, "Home Network"),
            ConnectionMode::UPnP => write!(f, "UPnP"),
            ConnectionMode::CustomPorts => write!(f, "Custom Ports"),
            ConnectionMode::Automatic => write!(f, "Automatic"),
        }
    }
}

impl<'de> Deserialize<'de> for ConnectionMode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ConnectionMode, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Home Network" => Ok(ConnectionMode::HomeNetwork),
            "UPnP" => Ok(ConnectionMode::UPnP),
            "Custom Ports" => Ok(ConnectionMode::CustomPorts),
            "Automatic" => Ok(ConnectionMode::Automatic),
            _ => Err(serde::de::Error::custom(format!(
                "Invalid ConnectionMode: {s:?}"
            ))),
        }
    }
}

impl Serialize for ConnectionMode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            ConnectionMode::HomeNetwork => "Home Network",
            ConnectionMode::UPnP => "UPnP",
            ConnectionMode::CustomPorts => "Custom Ports",
            ConnectionMode::Automatic => "Automatic",
        };
        serializer.serialize_str(s)
    }
}