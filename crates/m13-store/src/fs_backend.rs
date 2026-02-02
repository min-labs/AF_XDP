#![cfg(feature = "std")]

use crate::backend::StorageBackend;
use m13_core::{M13Error, M13Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
// FIX: Explicitly import Vec and format! to handle no_std crate context
use std::vec::Vec; 
use std::format;

pub struct FileSystemBackend {
    root: PathBuf,
}

impl FileSystemBackend {
    pub fn new(path: &str) -> std::io::Result<Self> {
        fs::create_dir_all(path)?;
        Ok(Self { root: PathBuf::from(path) })
    }

    fn get_path(&self, id: u32) -> PathBuf {
        self.root.join(format!("bundle_{}.bin", id))
    }
}

impl StorageBackend for FileSystemBackend {
    fn write(&mut self, id: u32, data: &[u8]) -> M13Result<()> {
        let path = self.get_path(id);
        let tmp_path = path.with_extension("tmp");

        // 1. Write .tmp
        {
            let mut file = OpenOptions::new()
                .write(true).create(true).truncate(true)
                .open(&tmp_path).map_err(|_| M13Error::HalError)?;
            
            file.write_all(data).map_err(|_| M13Error::HalError)?;
            
            // 2. FSYNC (Critical)
            file.sync_all().map_err(|_| M13Error::HalError)?;
        }

        // 3. Rename (Atomic)
        fs::rename(tmp_path, path).map_err(|_| M13Error::HalError)?;
        
        // 4. Sync Parent Dir
        if let Ok(f) = File::open(&self.root) { let _ = f.sync_all(); }

        Ok(())
    }

    fn read(&self, id: u32) -> M13Result<Vec<u8>> {
        let path = self.get_path(id);
        let mut file = File::open(path).map_err(|_| M13Error::InvalidState)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|_| M13Error::HalError)?;
        Ok(buf)
    }

    fn delete(&mut self, id: u32) -> M13Result<()> {
        let path = self.get_path(id);
        if path.exists() {
             fs::remove_file(path).map_err(|_| M13Error::HalError)
        } else {
             Ok(())
        }
    }
    
    fn exists(&self, id: u32) -> bool {
        self.get_path(id).exists()
    }
}