#[cfg(feature = "std")]
mod tests {
    use m13_store::{BundleStore, fs_backend::FileSystemBackend};
    use rand_core::OsRng;
    use std::boxed::Box;
    use std::fs;

    #[test]
    fn test_passive_zeroization_on_reboot() {
        let test_dir = "./test_store_sec";
        let _ = fs::remove_dir_all(test_dir);
        let id = 99;
        let payload = b"Classified Coordinates";

        // Session 1: Write Data
        {
            let backend = FileSystemBackend::new(test_dir).unwrap();
            let mut store = BundleStore::new(Box::new(backend), OsRng);
            store.commit(id, payload).expect("Commit failed");
            
            // Verify Disk Content is Encrypted
            let path = format!("{}/bundle_{}.bin", test_dir, id);
            let raw_disk = fs::read(path).unwrap();
            assert_ne!(raw_disk, payload, "Data stored in plaintext!");
        } // Store drops -> Volatile Anchor is lost (Simulating Power Cut)

        // Session 2: Reboot
        {
            // Backend points to same disk, but RNG generates NEW Volatile Seed
            let backend = FileSystemBackend::new(test_dir).unwrap();
            let store = BundleStore::new(Box::new(backend), OsRng);
            
            // Try to recover
            let result = store.retrieve(id).unwrap();
            
            // Should be GARBAGE because seed changed
            assert_ne!(result, payload, "Data survived power loss! Zeroization failed.");
        }
        let _ = fs::remove_dir_all(test_dir);
    }
}