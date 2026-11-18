use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Connection {
    #[serde(skip)]
    pub id: String,
    pub name: String,
    pub folder: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub password: String,
    /// DPI-schaal van de remote sessie in procenten (100, 125, 150, 200 ...).
    pub scale: u32,
    pub dynamic_resolution: bool,
    pub smart_sizing: bool,
    pub fullscreen: bool,
    pub multimon: bool,
    pub notes: String,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            folder: String::new(),
            host: String::new(),
            port: 3389,
            username: String::new(),
            domain: String::new(),
            password: String::new(),
            scale: 100,
            dynamic_resolution: true,
            smart_sizing: true,
            fullscreen: false,
            multimon: false,
            notes: String::new(),
        }
    }
}
