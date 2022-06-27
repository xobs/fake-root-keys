mod keywrap;
use keywrap::*;

use sha2::Digest;

use crate::api::*;
use core::num::NonZeroUsize;
use utralib::generated::*;

use crate::api::PasswordType;
use crate::bcrypt::*;

use core::cell::RefCell;
use core::convert::TryInto;
use core::mem::size_of;

// TODO: add hardware acceleration for BCRYPT so we can hit the OWASP target without excessive UX delay
const BCRYPT_COST: u32 = 7; // 10 is the minimum recommended by OWASP; takes 5696 ms to verify @ 10 rounds; 804 ms to verify 7 rounds

/// Maximum number of times the global rollback limiter can be updated. Every time this is updated,
/// the firmware has to be re-signed, the gateware ROM re-injected, and the PDDB system key updated.
///
/// N.B.: As of Xous 0.9.6 we don't have a call to update the anti-rollback count, we have only provisioned for
/// that call to exist sometime in the future.
const MAX_ROLLBACK_LIMIT: u8 = 255;

#[allow(dead_code)]
/// location of the csr.csv that's appended on gateware images, used for USB updates.
const CSR_CSV_OFFSET: usize = 0x27_7000;

#[derive(Debug, Copy, Clone)]
pub(crate) enum FpgaKeySource {
    Bbram,
    Efuse,
}
const BITSTREAM_CTL0_CMD: u32 = 0x3000_a001;

/// This structure is mapped into the password cache page and can be zero-ized at any time
/// we avoid using fancy Rust structures because everything has to "make sense" after a forced zero-ization
/// The "password" here is generated as follows:
///   `user plaintext (up to first 72 bytes) -> bcrypt (24 bytes) -> sha512trunc256 -> [u8; 32]`
/// The final sha512trunc256 expansion is because we will use this to XOR against secret keys stored in
/// the KEYROM that may be up to 256 bits in length. For shorter keys, the hashed password is simply truncated.
#[repr(C)]
struct PasswordCache {
    hashed_boot_pw: [u8; 32],
    hashed_boot_pw_valid: u32, // non-zero for valid
    hashed_update_pw: [u8; 32],
    hashed_update_pw_valid: u32,
    fpga_key: [u8; 32],
    fpga_key_valid: u32,
}

struct KeyRomLocs {}
#[allow(dead_code)]
impl KeyRomLocs {
    const FPGA_KEY: u8 = 0x00;
    const SELFSIGN_PRIVKEY: u8 = 0x08;
    const SELFSIGN_PUBKEY: u8 = 0x10;
    const DEVELOPER_PUBKEY: u8 = 0x18;
    const THIRDPARTY_PUBKEY: u8 = 0x20;
    const USER_KEY: u8 = 0x28;
    const PEPPER: u8 = 0xf8;
    const FPGA_MIN_REV: u8 = 0xfc;
    const LOADER_MIN_REV: u8 = 0xfd;
    const GLOBAL_ROLLBACK: u8 = 0xfe;
    const CONFIG: u8 = 0xff;
}

pub struct KeyField {
    mask: u32,
    offset: u32,
}
impl KeyField {
    pub const fn new(width: u32, offset: u32) -> Self {
        let mask = (1 << width) - 1;
        KeyField { mask, offset }
    }
    pub fn ms(&self, value: u32) -> u32 {
        let ms_le = (value & self.mask) << self.offset;
        ms_le.to_be()
    }
}
#[allow(dead_code)]
pub(crate) mod keyrom_config {
    use crate::KeyField;
    pub const VERSION_MINOR: KeyField = KeyField::new(8, 0);
    pub const VERSION_MAJOR: KeyField = KeyField::new(8, 8);
    pub const DEVBOOT_DISABLE: KeyField = KeyField::new(1, 16);
    pub const ANTIROLLBACK_ENA: KeyField = KeyField::new(1, 17);
    pub const ANTIROLLFORW_ENA: KeyField = KeyField::new(1, 18);
    pub const FORWARD_REV_LIMIT: KeyField = KeyField::new(4, 19);
    pub const FORWARD_MINOR_LIMIT: KeyField = KeyField::new(4, 23);
    pub const INITIALIZED: KeyField = KeyField::new(1, 27);
}

pub(crate) struct RootKeys {
    keyrom: utralib::CSR<u32>,
    gateware_mr: xous::MemoryRange,
    /// regions of RAM that holds all plaintext passwords, keys, and temp data. stuck in two well-defined page so we can
    /// zero-ize it upon demand, without guessing about stack frames and/or Rust optimizers removing writes
    sensitive_data: RefCell<xous::MemoryRange>, // this gets purged at least on every suspend, but ideally purged sooner than that
    pass_cache: xous::MemoryRange, // this can be purged based on a policy, as set below
    boot_password_policy: PasswordRetentionPolicy,
    cur_password_type: Option<PasswordType>, // for tracking which password we're dealing with at the UX layer
    fake_key: [u8; 32], // a base set of random numbers used to respond to invalid keyloc requests in AES operations
}

impl<'a> RootKeys {
    pub fn new() -> RootKeys {
        let keyrom = xous::syscall::map_memory(
            xous::MemoryAddress::new(utra::keyrom::HW_KEYROM_BASE),
            None,
            4096,
            xous::MemoryFlags::R | xous::MemoryFlags::W,
        )
        .expect("couldn't map keyrom CSR range");
        // read-only memory maps. even if we don't refer to them, we map them into our process
        // so that no other processes can claim them
        let gateware = xous::syscall::map_memory(
            Some(
                NonZeroUsize::new((xous::SOC_MAIN_GW_LOC + xous::FLASH_PHYS_BASE) as usize)
                    .unwrap(),
            ),
            None,
            xous::SOC_MAIN_GW_LEN as usize,
            xous::MemoryFlags::R,
        )
        .expect("couldn't map in the SoC gateware region");

        let mut sensitive_data = xous::syscall::map_memory(
            None,
            None,
            0x1000,
            xous::MemoryFlags::R | xous::MemoryFlags::W,
        )
        .expect("couldn't map sensitive data page");
        let mut pass_cache = xous::syscall::map_memory(
            None,
            None,
            0x1000,
            xous::MemoryFlags::R | xous::MemoryFlags::W,
        )
        .expect("couldn't map sensitive data page");
        // make sure the caches start out as zeros
        for w in pass_cache.as_slice_mut::<u32>().iter_mut() {
            *w = 0;
        }
        for w in sensitive_data.as_slice_mut::<u32>().iter_mut() {
            *w = 0;
        }

        // respond to invalid key indices with a "fake" AES key. We try to foil attempts to "probe out" the
        // oracle to discover the presence of null keys.
        let fake_key: [u8; 32] = [4; 32];

        let keys = RootKeys {
            keyrom: CSR::new(keyrom.as_mut_ptr() as *mut u32),
            gateware_mr: gateware,
            sensitive_data: RefCell::new(sensitive_data),
            pass_cache,
            boot_password_policy: PasswordRetentionPolicy::AlwaysKeep,
            cur_password_type: None,
            fake_key,
        };
        /*
        // dumps the key enclave -- in a format for Renode integration. Or if you just wanted to steal all the keys.
        // PS: you still need to know the passwords to decrypt the keys
        for i in 0..256 {
            keys.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, i);
            log::info!("this.data[0x{:x}] = 0x{:x};", i, keys.keyrom.rf(utra::keyrom::DATA_DATA));
        } */

        keys
    }
    pub fn gateware(&self) -> &[u8] {
        self.gateware_mr.as_slice::<u8>()
    }

    /// takes a root key and computes the current rollback state of the key by hashing it
    /// MAX_ROLLBACK_LIMIT - GLOBAL_ROLLBACK times.
    fn compute_key_rollback(&mut self, key: &mut [u8]) {
        assert!(key.len() == 32, "Key length is incorrect");
        self.keyrom.wfo(
            utra::keyrom::ADDRESS_ADDRESS,
            KeyRomLocs::GLOBAL_ROLLBACK as u32,
        );
        let mut rollback_limit = self.keyrom.rf(utra::keyrom::DATA_DATA);
        if rollback_limit > 255 {
            rollback_limit = 255;
        } // prevent increment-up attacks that roll over
        log::debug!("rollback_limit: {}", rollback_limit);
        for _i in 0..MAX_ROLLBACK_LIMIT - rollback_limit as u8 {
            let mut hasher = sha2::Sha512_256::new();
            hasher.update(&key);
            let digest = hasher.finalize();
            assert!(digest.len() == 32, "Digest had an incorrect length");
            key.copy_from_slice(&digest);
            #[cfg(feature = "hazardous-debug")]
            if _i >= (MAX_ROLLBACK_LIMIT - 3) {
                log::info!("iter {} key {:x?}", _i, key);
            }
        }
    }
    pub fn kwp_op(&mut self, kwp: &mut KeyWrapper) {
        let mut key = match kwp.key_index {
            KeyRomLocs::USER_KEY => {
                let mut key_enc = self.read_key_256(KeyRomLocs::USER_KEY);
                let pcache: &PasswordCache =
                    unsafe { &*(self.pass_cache.as_ptr() as *const PasswordCache) };
                if pcache.hashed_boot_pw_valid == 0 {
                    self.purge_password(PasswordType::Boot);
                    log::warn!("boot password isn't valid! Returning bogus results.");
                }
                for (key, &pw) in key_enc.iter_mut().zip(pcache.hashed_boot_pw.iter()) {
                    *key = *key ^ pw;
                }
                if self.boot_password_policy == PasswordRetentionPolicy::AlwaysPurge {
                    self.purge_password(PasswordType::Boot);
                }
                key_enc
            }
            _ => {
                self.fake_key[0] = kwp.key_index;
                self.fake_key
            }
        };
        #[cfg(feature = "hazardous-debug")]
        log::debug!("root user key: {:x?}", key);
        self.compute_key_rollback(&mut key);
        #[cfg(feature = "hazardous-debug")]
        log::debug!("root user key (anti-rollback): {:x?}", key);
        let keywrapper = Aes256KeyWrap::new(&key);
        match kwp.op {
            KeyWrapOp::Wrap => {
                match keywrapper.encapsulate(&kwp.data[..kwp.len as usize]) {
                    Ok(wrapped) => {
                        for (&src, dst) in wrapped.iter().zip(kwp.data.iter_mut()) {
                            *dst = src;
                        }
                        kwp.len = wrapped.len() as u32;
                        kwp.result = None;
                        // this is an un-used field but...why not?
                        kwp.expected_len = wrapped.len() as u32;
                    }
                    Err(e) => {
                        kwp.result = Some(e);
                    }
                }
            }
            KeyWrapOp::Unwrap => {
                match keywrapper
                    .decapsulate(&kwp.data[..kwp.len as usize], kwp.expected_len as usize)
                {
                    Ok(unwrapped) => {
                        for (&src, dst) in unwrapped.iter().zip(kwp.data.iter_mut()) {
                            *dst = src;
                        }
                        kwp.len = unwrapped.len() as u32;
                        kwp.result = None;
                    }
                    Err(e) => {
                        kwp.result = Some(e);
                    }
                }
            }
        }
    }

    /// returns None if there is an obvious problem with the JTAG interface
    /// otherwise returns the result. "secured" would be the most paranoid setting
    /// which is all the bits burned. There are other combinations that are also
    /// totally valid based on your usage scenario, however, but the have yet to
    /// be implemented (see the JTAG crate for more info); however, we reflect
    /// all of the calls through rootkeys so we aren't exposing JTAG attack surface
    /// to the rest of the world.
    pub fn is_efuse_secured(&self) -> Option<bool> {
        Some(true)
    }
    pub fn fpga_key_source(&self) -> FpgaKeySource {
        let mut words = self.gateware()[..4096].chunks(4);
        loop {
            if let Some(word) = words.next() {
                let cwd = u32::from_be_bytes(word[0..4].try_into().unwrap());
                if cwd == BITSTREAM_CTL0_CMD {
                    let ctl0 = u32::from_be_bytes(words.next().unwrap()[0..4].try_into().unwrap());
                    if ctl0 & 0x8000_0000 == 0 {
                        return FpgaKeySource::Bbram;
                    } else {
                        return FpgaKeySource::Efuse;
                    }
                }
            } else {
                log::error!("didn't find FpgaKeySource in plaintext header");
                panic!("didn't find FpgaKeySource in plaintext header");
            }
        }
    }
    pub fn is_jtag_working(&self) -> bool {
        true
    }

    pub fn purge_user_password(&mut self, pw_type: AesRootkeyType) {
        match pw_type {
            AesRootkeyType::User0 => self.purge_password(PasswordType::Boot),
            _ => {
                log::warn!("Requested to purge a password for a key that we don't have. Ignoring.")
            }
        }
    }
    pub fn purge_password(&mut self, pw_type: PasswordType) {
        unsafe {
            let pcache_ptr: *mut PasswordCache = self.pass_cache.as_mut_ptr() as *mut PasswordCache;
            match pw_type {
                PasswordType::Boot => {
                    for p in (*pcache_ptr).hashed_boot_pw.iter_mut() {
                        *p = 0;
                    }
                    (*pcache_ptr).hashed_boot_pw_valid = 0;
                }
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    pub fn update_policy(&mut self, policy: Option<PasswordRetentionPolicy>) {
        let pw_type = if let Some(cur_type) = self.cur_password_type {
            cur_type
        } else {
            log::error!("got an unexpected policy update from the UX");
            return;
        };
        if let Some(p) = policy {
            match pw_type {
                PasswordType::Boot => self.boot_password_policy = p,
            };
        } else {
            match pw_type {
                PasswordType::Boot => PasswordRetentionPolicy::AlwaysPurge,
            };
        }
        // once the policy has been set, revert the current type to None
        self.cur_password_type = None;
    }

    /// Plaintext password is passed as a &str. Any copies internally are destroyed. Caller is responsible for destroying the &str original.
    /// Performs a bcrypt hash of the password, with the currently set salt; does not store the plaintext after exit.
    pub fn hash_and_save_password(&mut self, pw: &str) {
        let pw_type = if let Some(cur_type) = self.cur_password_type {
            cur_type
        } else {
            log::error!("got an unexpected password from the UX");
            return;
        };
        let mut hashed_password: [u8; 24] = [0; 24];
        let mut salt = self.get_salt();
        println!("pw_type: {}  Salt: {:?}", pw_type as u8, salt);
        // we change the salt ever-so-slightly for every password. This doesn't make any one password more secure;
        // but it disallows guessing all the passwords with a single off-the-shelf hashcat run.
        salt[0] ^= pw_type as u8;

        // the bcrypt function takes the plaintext password and makes one copy to prime the blowfish bcrypt
        // cipher. It is responsible for erasing this state.
        let start_time = std::time::Instant::now();
        bcrypt(BCRYPT_COST, &salt, pw, &mut hashed_password); // note: this internally makes a copy of the password, and destroys it
        let elapsed = start_time.elapsed().as_millis();
        log::info!(
            "bcrypt cost: {} time: {}ms  hashed_password: {:?}",
            BCRYPT_COST,
            elapsed,
            hashed_password
        ); // benchmark to figure out how to set cost parameter

        // expand the 24-byte (192-bit) bcrypt result into 256 bits, so we can use it directly as XOR key material
        // against 256-bit AES and curve25519 keys
        // for such a small hash, software is the most performant choice
        let mut hasher = sha2::Sha512_256::new();
        hasher.update(hashed_password);
        let digest = hasher.finalize();

        let pcache_ptr: *mut PasswordCache = self.pass_cache.as_mut_ptr() as *mut PasswordCache;
        unsafe {
            match pw_type {
                PasswordType::Boot => {
                    for (&src, dst) in digest.iter().zip((*pcache_ptr).hashed_boot_pw.iter_mut()) {
                        *dst = src;
                    }
                    (*pcache_ptr).hashed_boot_pw_valid = 1;
                }
            }
        }
    }

    /// Reads a 256-bit key at a given index offset
    fn read_key_256(&mut self, index: u8) -> [u8; 32] {
        let mut key: [u8; 32] = [0; 32];
        for (addr, word) in key.chunks_mut(4).into_iter().enumerate() {
            self.keyrom
                .wfo(utra::keyrom::ADDRESS_ADDRESS, index as u32 + addr as u32);
            let keyword = self.keyrom.rf(utra::keyrom::DATA_DATA);
            for (&byte, dst) in keyword.to_be_bytes().iter().zip(word.iter_mut()) {
                *dst = byte;
            }
        }
        key
    }
    /// Reads a 128-bit key at a given index offset
    fn read_key_128(&mut self, index: u8) -> [u8; 16] {
        let mut key: [u8; 16] = [0; 16];
        for (addr, word) in key.chunks_mut(4).into_iter().enumerate() {
            self.keyrom
                .wfo(utra::keyrom::ADDRESS_ADDRESS, index as u32 + addr as u32);
            let keyword = self.keyrom.rf(utra::keyrom::DATA_DATA);
            for (&byte, dst) in keyword.to_be_bytes().iter().zip(word.iter_mut()) {
                *dst = byte;
            }
        }
        key
    }

    /// Returns the `salt` needed for the `bcrypt` routine.
    /// This routine handles the special-case of being unitialized: in that case, we need to get
    /// salt from a staging area, and not our KEYROM. However, `setup_key_init` must be called
    /// first to ensure that the staging area has a valid salt.
    fn get_salt(&mut self) -> [u8; 16] {
        if !self.is_initialized() {
            // we're not initialized, use the salt that should already be in the staging area
            let mut key: [u8; 16] = [0; 16];
            for (word, &keyword) in key.chunks_mut(4).into_iter()
            .zip(self.sensitive_data.borrow_mut().as_slice::<u32>() // get the sensitive_data as a slice &mut[u32]
            [KeyRomLocs::PEPPER as usize..KeyRomLocs::PEPPER as usize + 128/(size_of::<u32>()*8)].iter()) {
                for (&byte, dst) in keyword.to_be_bytes().iter().zip(word.iter_mut()) {
                    *dst = byte;
                }
            }
            key
        } else {
            self.read_key_128(KeyRomLocs::PEPPER)
        }
    }

    /// Called by the UX layer to track which password we're currently requesting
    pub fn set_ux_password_type(&mut self, cur_type: Option<PasswordType>) {
        self.cur_password_type = cur_type;
    }
    /// Called by the UX layer to check which password request is in progress
    #[allow(dead_code)]
    pub fn get_ux_password_type(&self) -> Option<PasswordType> {
        self.cur_password_type
    }

    pub fn is_initialized(&mut self) -> bool {
        self.keyrom
            .wfo(utra::keyrom::ADDRESS_ADDRESS, KeyRomLocs::CONFIG as u32);
        let config = self.keyrom.rf(utra::keyrom::DATA_DATA);
        if config & keyrom_config::INITIALIZED.ms(1) != 0 {
            true
        } else {
            false
        }
    }
    pub fn is_pcache_boot_password_valid(&self) -> bool {
        let pcache: &mut PasswordCache =
            unsafe { &mut *(self.pass_cache.as_mut_ptr() as *mut PasswordCache) };
        if pcache.hashed_boot_pw_valid == 0 {
            false
        } else {
            true
        }
    }

    #[allow(dead_code)]
    #[cfg(feature = "hazardous-debug")]
    pub fn printkeys(&mut self) {
        // dump the keystore -- used to confirm that patching worked right. does not get compiled in when hazardous-debug is not enable.
        for addr in 0..256 {
            self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, addr);
            self.sensitive_data.borrow_mut().as_slice_mut::<u32>()[addr as usize] =
                self.keyrom.rf(utra::keyrom::DATA_DATA);
            log::info!(
                "{:02x}: 0x{:08x}",
                addr,
                self.sensitive_data.borrow_mut().as_slice::<u32>()[addr as usize]
            );
        }
    }
}
