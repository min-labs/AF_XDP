use m13_hal::{PhysicalInterface, LinkProperties};
use m13_core::M13Error;

struct Loopback {
    mtu: usize,
}

impl PhysicalInterface for Loopback {
    fn properties(&self) -> LinkProperties {
        // FIX: Read the actual field to satisfy the compiler
        LinkProperties { mtu: self.mtu, bandwidth_bps: 0, is_reliable: true }
    }
    fn send(&mut self, frame: &[u8]) -> nb::Result<usize, M13Error> {
        Ok(frame.len())
    }
    fn recv<'a>(&mut self, _buffer: &'a mut [u8]) -> nb::Result<usize, M13Error> {
        Err(nb::Error::WouldBlock)
    }
}

#[test]
fn test_trait_object_safety() {
    let mut dev = Loopback { mtu: 1500 };
    let obj: &mut dyn PhysicalInterface = &mut dev;
    
    assert_eq!(obj.properties().mtu, 1500);
    assert!(obj.recv(&mut [0u8; 10]).is_err());
}

#[test]
fn test_security_contract() {
    // FIX: Add allow(dead_code) because this struct exists PURELY to test
    // that the compiler accepts the '!' return type implementation.
    #[allow(dead_code)]
    struct PanicDevice;
    
    use m13_hal::SecurityModule;
    
    impl SecurityModule for PanicDevice {
        fn get_random_bytes(&mut self, _buf: &mut [u8]) -> m13_core::M13Result<()> { Ok(()) }
        fn sign_digest(&mut self, _digest: &[u8], _sig: &mut [u8]) -> m13_core::M13Result<usize> { Ok(0) }
        
        fn panic_and_sanitize(&self) -> ! {
            loop {} 
        }
    }
    
    // We don't need to instantiate it to prove the trait is valid Rust code.
}