use std::path::PathBuf;

pub fn get_config_dir() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".dood");
    std::fs::create_dir_all(&path).ok();
    path
}

pub fn get_db_path() -> PathBuf {
    let mut path = get_config_dir();
    path.push("dood.db");
    path
}

pub fn get_keys_dir() -> PathBuf {
    let mut path = get_config_dir();
    path.push("keys");
    std::fs::create_dir_all(&path).ok();
    path
}
