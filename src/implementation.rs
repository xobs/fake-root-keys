mod oracle;
use oracle::*;
mod keywrap;
use keywrap::*;
pub use oracle::FpgaKeySource;

use sha2::Digest;

use utralib::generated::*;
use crate::api::*;
use core::num::NonZeroUsize;

use crate::bcrypt::*;
use crate::api::PasswordType;

use core::convert::TryInto;
use ed25519_dalek::{Keypair, Signature};
use core::mem::size_of;
use core::cell::RefCell;

use aes::Aes256;
use aes::cipher::{KeyInit, BlockDecrypt, BlockEncrypt};
use cipher::generic_array::GenericArray;

use crate::{SignatureResult, GatewareRegion, MetadataInFlash};

// TODO: add hardware acceleration for BCRYPT so we can hit the OWASP target without excessive UX delay
const BCRYPT_COST: u32 = 7;   // 10 is the minimum recommended by OWASP; takes 5696 ms to verify @ 10 rounds; 804 ms to verify 7 rounds

/// Maximum number of times the global rollback limiter can be updated. Every time this is updated,
/// the firmware has to be re-signed, the gateware ROM re-injected, and the PDDB system key updated.
///
/// N.B.: As of Xous 0.9.6 we don't have a call to update the anti-rollback count, we have only provisioned for
/// that call to exist sometime in the future.
const MAX_ROLLBACK_LIMIT: u8 = 255;

/// Size of the total area allocated for signatures. It is equal to the size of one FLASH sector, which is the smallest
/// increment that can be erased.
const SIGBLOCK_SIZE: u32 = 0x1000;
/// location of the csr.csv that's appended on gateware images, used for USB updates.
const METADATA_OFFSET: usize = 0x27_6000;
#[allow(dead_code)]
/// location of the csr.csv that's appended on gateware images, used for USB updates.
const CSR_CSV_OFFSET: usize  = 0x27_7000;
/// offset of the gateware self-signature area
const SELFSIG_OFFSET: usize  = 0x27_F000;

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

#[repr(C)]
struct SignatureInFlash {
    pub version: u32,
    pub signed_len: u32,
    pub signature: [u8; 64],
}
pub enum SignatureType {
    Loader,
    Gateware,
    Kernel,
}

struct KeyRomLocs {}
#[allow(dead_code)]
impl KeyRomLocs {
    const FPGA_KEY:            u8 = 0x00;
    const SELFSIGN_PRIVKEY:    u8 = 0x08;
    const SELFSIGN_PUBKEY:     u8 = 0x10;
    const DEVELOPER_PUBKEY:    u8 = 0x18;
    const THIRDPARTY_PUBKEY:   u8 = 0x20;
    const USER_KEY:   u8 = 0x28;
    const PEPPER:     u8 = 0xf8;
    const FPGA_MIN_REV:   u8 = 0xfc;
    const LOADER_MIN_REV: u8 = 0xfd;
    const GLOBAL_ROLLBACK: u8 = 0xfe;
    const CONFIG:     u8 = 0xff;
}

pub struct KeyField {
    mask: u32,
    offset: u32,
}
impl KeyField {
    pub const fn new(width: u32, offset: u32) -> Self {
        let mask = (1 << width) - 1;
        KeyField {
            mask,
            offset,
        }
    }
    pub fn ms(&self, value: u32) -> u32 {
        let ms_le = (value & self.mask) << self.offset;
        ms_le.to_be()
    }
}
#[allow(dead_code)]
pub(crate) mod keyrom_config {
    use crate::KeyField;
    pub const VERSION_MINOR:       KeyField = KeyField::new(8, 0 );
    pub const VERSION_MAJOR:       KeyField = KeyField::new(8, 8 );
    pub const DEVBOOT_DISABLE:     KeyField = KeyField::new(1, 16);
    pub const ANTIROLLBACK_ENA:    KeyField = KeyField::new(1, 17);
    pub const ANTIROLLFORW_ENA:    KeyField = KeyField::new(1, 18);
    pub const FORWARD_REV_LIMIT:   KeyField = KeyField::new(4, 19);
    pub const FORWARD_MINOR_LIMIT: KeyField = KeyField::new(4, 23);
    pub const INITIALIZED:         KeyField = KeyField::new(1, 27);
}

/// helper routine that will reverse the order of bits. uses a divide-and-conquer approach.
pub(crate) fn bitflip(input: &[u8], output: &mut [u8]) {
    assert!((input.len() % 4 == 0) && (output.len() % 4 == 0) && (input.len() == output.len()));
    for (src, dst) in
    input.chunks(4).into_iter()
    .zip(output.chunks_mut(4).into_iter()) {
        let mut word = u32::from_le_bytes(src.try_into().unwrap()); // read in as LE
        word = ((word >> 1) & 0x5555_5555) | ((word & (0x5555_5555)) << 1);
        word = ((word >> 2) & 0x3333_3333) | ((word & (0x3333_3333)) << 2);
        word = ((word >> 4) & 0x0F0F_0F0F) | ((word & (0x0F0F_0F0F)) << 4);
        // copy out as BE, this performs the final byte-level swap needed by the divde-and-conquer algorithm
        for (&s, d) in word.to_be_bytes().iter().zip(dst.iter_mut()) {
            *d = s;
        }
    }
}

pub(crate) struct RootKeys {
    keyrom: utralib::CSR<u32>,
    gateware_mr: xous::MemoryRange,
    gateware_base: u32,
    staging_mr: xous::MemoryRange,
    staging_base: u32,
    loader_code_mr: xous::MemoryRange,
    loader_code_base: u32,
    kernel_mr: xous::MemoryRange,
    kernel_base: u32,
    /// regions of RAM that holds all plaintext passwords, keys, and temp data. stuck in two well-defined page so we can
    /// zero-ize it upon demand, without guessing about stack frames and/or Rust optimizers removing writes
    sensitive_data: RefCell<xous::MemoryRange>, // this gets purged at least on every suspend, but ideally purged sooner than that
    pass_cache: xous::MemoryRange,  // this can be purged based on a policy, as set below
    boot_password_policy: PasswordRetentionPolicy,
    update_password_policy: PasswordRetentionPolicy,
    cur_password_type: Option<PasswordType>, // for tracking which password we're dealing with at the UX layer
    ticktimer: ticktimer_server::Ticktimer,
    xns: xous_names::XousNames,
    jtag: jtag::Jtag,
    fake_key: [u8; 32], // a base set of random numbers used to respond to invalid keyloc requests in AES operations
}

impl<'a> RootKeys {
    pub fn new() -> RootKeys {
        let xns = xous_names::XousNames::new().unwrap();
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
            Some(NonZeroUsize::new((xous::SOC_MAIN_GW_LOC + xous::FLASH_PHYS_BASE) as usize).unwrap()),
            None,
            xous::SOC_MAIN_GW_LEN as usize,
            xous::MemoryFlags::R,
        ).expect("couldn't map in the SoC gateware region");
        let staging = xous::syscall::map_memory(
            Some(NonZeroUsize::new((xous::SOC_STAGING_GW_LOC + xous::FLASH_PHYS_BASE) as usize).unwrap()),
            None,
            xous::SOC_STAGING_GW_LEN as usize,
            xous::MemoryFlags::R,
        ).expect("couldn't map in the SoC staging region");
        let loader_code = xous::syscall::map_memory(
            Some(NonZeroUsize::new((xous::LOADER_LOC + xous::FLASH_PHYS_BASE) as usize).unwrap()),
            None,
            xous::LOADER_CODE_LEN as usize,
            xous::MemoryFlags::R,
        ).expect("couldn't map in the loader code region");
        let kernel = xous::syscall::map_memory(
            Some(NonZeroUsize::new((xous::KERNEL_LOC + xous::FLASH_PHYS_BASE) as usize).unwrap()),
            None,
            xous::KERNEL_LEN as usize,
            xous::MemoryFlags::R,
        ).expect("couldn't map in the kernel region");

        let mut sensitive_data = xous::syscall::map_memory(
            None,
            None,
            0x1000,
            xous::MemoryFlags::R | xous::MemoryFlags::W,
        ).expect("couldn't map sensitive data page");
        let mut pass_cache = xous::syscall::map_memory(
            None,
            None,
            0x1000,
            xous::MemoryFlags::R | xous::MemoryFlags::W,
        ).expect("couldn't map sensitive data page");
        // make sure the caches start out as zeros
        for w in pass_cache.as_slice_mut::<u32>().iter_mut() {
            *w = 0;
        }
        for w in sensitive_data.as_slice_mut::<u32>().iter_mut() {
            *w = 0;
        }

        let jtag = jtag::Jtag::new(&xns).expect("couldn't connect to JTAG server");
        // respond to invalid key indices with a "fake" AES key. We try to foil attempts to "probe out" the
        // oracle to discover the presence of null keys.
        let mut fake_key: [u8; 32] = [4; 32];

        let keys = RootKeys {
            keyrom: CSR::new(keyrom.as_mut_ptr() as *mut u32),
            gateware_mr: gateware,
            gateware_base: xous::SOC_MAIN_GW_LOC,
            staging_mr: staging,
            staging_base: xous::SOC_STAGING_GW_LOC,
            loader_code_mr: loader_code,
            loader_code_base: xous::LOADER_LOC,
            kernel_mr: kernel,
            kernel_base: xous::KERNEL_LOC,
            sensitive_data: RefCell::new(sensitive_data),
            pass_cache,
            update_password_policy: PasswordRetentionPolicy::AlwaysPurge,
            boot_password_policy: PasswordRetentionPolicy::AlwaysKeep,
            cur_password_type: None,
            ticktimer: ticktimer_server::Ticktimer::new().expect("couldn't connect to ticktimer"),
            xns,
            jtag,
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
    pub fn gateware_base(&self) -> u32 { self.gateware_base }
    pub fn staging(&self) -> &[u8] {
        self.staging_mr.as_slice::<u8>()
    }
    pub fn staging_base(&self) -> u32 { self.staging_base }
    pub fn loader_code(&self) -> &[u8] {
        self.loader_code_mr.as_slice::<u8>()
    }
    pub fn loader_base(&self) -> u32 { self.loader_code_base }
    pub fn kernel(&self) -> &[u8] {
        self.kernel_mr.as_slice::<u8>()
    }
    pub fn kernel_base(&self) -> u32 { self.kernel_base }

    /// takes a root key and computes the current rollback state of the key by hashing it
    /// MAX_ROLLBACK_LIMIT - GLOBAL_ROLLBACK times.
    fn compute_key_rollback(&mut self, key: &mut [u8]) {
        assert!(key.len() == 32, "Key length is incorrect");
        self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, KeyRomLocs::GLOBAL_ROLLBACK as u32);
        let mut rollback_limit = self.keyrom.rf(utra::keyrom::DATA_DATA);
        if rollback_limit > 255 { rollback_limit = 255; } // prevent increment-up attacks that roll over
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
    /// This implementation creates and destroys the AES key schedule on every function call
    /// However, Rootkey operations are not meant to be used for streaming operations; they are typically
    /// used to secure subkeys, so a bit of overhead on each call is OK in order to not keep excess secret
    /// data laying around.
    /// ASSUME: the caller has confirmed that the user password is valid and in cache
    pub fn aes_op(&mut self, key_index: u8, op_type: AesOpType, block: &mut [u8; 16]) {
        let mut key = match key_index {
            KeyRomLocs::USER_KEY => {
                let mut key_enc = self.read_key_256(KeyRomLocs::USER_KEY);
                let pcache: &PasswordCache = unsafe{& *(self.pass_cache.as_ptr() as *const PasswordCache)};
                if pcache.hashed_boot_pw_valid == 0 {
                    self.purge_password(PasswordType::Boot);
                    log::warn!("boot password isn't valid! Returning bogus results.");
                }
                for (key, &pw) in
                key_enc.iter_mut().zip(pcache.hashed_boot_pw.iter()) {
                    *key = *key ^ pw;
                }
                if self.boot_password_policy == PasswordRetentionPolicy::AlwaysPurge {
                    self.purge_password(PasswordType::Boot);
                }
                key_enc
            },
            _ => {
                // within a single boot, return a stable, non-changing fake key based off of a single root
                // fake key. This will make it a bit harder for an attacker to "probe out" an oracle and see
                // which keys are null or which are populated.
                self.fake_key[0] = key_index;
                self.fake_key
            }
        };
        self.compute_key_rollback(&mut key);
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        match op_type {
            AesOpType::Decrypt => cipher.decrypt_block(block.try_into().unwrap()),
            AesOpType::Encrypt => cipher.encrypt_block(block.try_into().unwrap())
        }
    }
    pub fn aes_par_op(&mut self, key_index: u8, op_type: AesOpType, blocks: &mut[[u8; 16]; PAR_BLOCKS]) {
        let mut key = match key_index {
            KeyRomLocs::USER_KEY => {
                let mut key_enc = self.read_key_256(KeyRomLocs::USER_KEY);
                let pcache: &PasswordCache = unsafe{& *(self.pass_cache.as_ptr() as *const PasswordCache)};
                if pcache.hashed_boot_pw_valid == 0 {
                    self.purge_password(PasswordType::Boot);
                    log::warn!("boot password isn't valid! Returning bogus results.");
                }
                for (key, &pw) in
                key_enc.iter_mut().zip(pcache.hashed_boot_pw.iter()) {
                    *key = *key ^ pw;
                }
                if self.boot_password_policy == PasswordRetentionPolicy::AlwaysPurge {
                    self.purge_password(PasswordType::Boot);
                }
                key_enc
            },
            _ => {
                self.fake_key[0] = key_index;
                self.fake_key
            }
        };
        self.compute_key_rollback(&mut key);
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        match op_type {
            AesOpType::Decrypt => {
                for block in blocks.iter_mut() {
                    cipher.decrypt_block(block.try_into().unwrap());
                }
            },
            AesOpType::Encrypt => {
                for block in blocks.iter_mut() {
                    cipher.encrypt_block(block.try_into().unwrap());
                }
            }
        }
    }
    pub fn kwp_op(&mut self, kwp: &mut KeyWrapper) {
        let mut key = match kwp.key_index {
            KeyRomLocs::USER_KEY => {
                let mut key_enc = self.read_key_256(KeyRomLocs::USER_KEY);
                let pcache: &PasswordCache = unsafe{& *(self.pass_cache.as_ptr() as *const PasswordCache)};
                if pcache.hashed_boot_pw_valid == 0 {
                    self.purge_password(PasswordType::Boot);
                    log::warn!("boot password isn't valid! Returning bogus results.");
                }
                for (key, &pw) in
                key_enc.iter_mut().zip(pcache.hashed_boot_pw.iter()) {
                    *key = *key ^ pw;
                }
                if self.boot_password_policy == PasswordRetentionPolicy::AlwaysPurge {
                    self.purge_password(PasswordType::Boot);
                }
                key_enc
            },
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
                match keywrapper.decapsulate(&kwp.data[..kwp.len as usize], kwp.expected_len as usize) {
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
        if self.jtag.get_id().unwrap() != jtag::XCS750_IDCODE {
            return None;
        }
        if (self.jtag.get_raw_control_bits().expect("couldn't get control bits") & 0x3f) != 0x3F {
            return Some(false)
        } else {
            return Some(true)
        }
    }
    pub fn fpga_key_source(&self) -> FpgaKeySource {
        let mut words = self.gateware()[..4096].chunks(4);
        loop {
            if let Some(word) = words.next() {
                let cwd = u32::from_be_bytes(word[0..4].try_into().unwrap());
                if cwd == BITSTREAM_CTL0_CMD {
                    let ctl0 = u32::from_be_bytes(words.next().unwrap()[0..4].try_into().unwrap());
                    if ctl0 & 0x8000_0000 == 0 {
                        return FpgaKeySource::Bbram
                    } else {
                        return FpgaKeySource::Efuse
                    }
                }
            } else {
                log::error!("didn't find FpgaKeySource in plaintext header");
                panic!("didn't find FpgaKeySource in plaintext header");
            }
        }
    }
    pub fn is_jtag_working(&self) -> bool {
        if self.jtag.get_id().unwrap() == jtag::XCS750_IDCODE {
            true
        } else {
            false
        }
    }

    /// Checks that various registries are "fully populated", to ensure that the trusted set of servers
    /// have completely loaded before trying to move on. Many of the security properties of the system
    /// rely upon a trusted set of servers claiming unique and/or enumerated tokens or slots, and then
    /// disallowing any new registrations after that point. This call prevents trusted operations from
    /// occurring if some of these servers have failed to check in.
    fn xous_init_interlock(&self) {
        // loop {
        //     if self.xns.trusted_init_done().expect("couldn't query init done status on xous-names") {
        //         break;
        //     } else {
        //         log::warn!("trusted init of xous-names not finished, rootkeys is holding off on sensitive operations");
        //         self.ticktimer.sleep_ms(650).expect("couldn't sleep");
        //     }
        // }
        // loop {
        //     if self.gam.get().trusted_init_done().expect("couldn't query init done status on GAM") {
        //         break;
        //     } else {
        //         log::warn!("trusted init of GAM not finished, rootkeys is holding off on sensitive operations");
        //         self.ticktimer.sleep_ms(650).expect("couldn't sleep");
        //     }
        // }
    }
    pub fn purge_user_password(&mut self, pw_type: AesRootkeyType) {
        match pw_type {
            AesRootkeyType::User0 => self.purge_password(PasswordType::Boot),
            _ => log::warn!("Requested to purge a password for a key that we don't have. Ignoring."),
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
                PasswordType::Update => {
                    for p in (*pcache_ptr).hashed_update_pw.iter_mut() {
                        *p = 0;
                    }
                    (*pcache_ptr).hashed_update_pw_valid = 0;

                    for p in (*pcache_ptr).fpga_key.iter_mut() {
                        *p = 0;
                    }
                    (*pcache_ptr).fpga_key_valid = 0;
                }
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    pub fn purge_sensitive_data(&mut self) {
        for d in self.sensitive_data.borrow_mut().as_slice_mut::<u32>().iter_mut() {
            *d = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    fn populate_sensitive_data(&mut self) {
        for (addr, d) in self.sensitive_data.borrow_mut().as_slice_mut::<u32>().iter_mut().enumerate() {
            if addr > 255 {
                break;
            }
            self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, addr as u32);
            let keyword = self.keyrom.rf(utra::keyrom::DATA_DATA);
            *d = keyword;
        }
    }
    fn replace_fpga_key(&mut self) {
        unimplemented!()
    }

    pub fn suspend(&mut self) {
        match self.boot_password_policy {
            PasswordRetentionPolicy::AlwaysKeep => {
                ()
            },
            _ => {
                self.purge_password(PasswordType::Boot);
            }
        }
        match self.update_password_policy {
            PasswordRetentionPolicy::AlwaysKeep => {
                ()
            },
            _ => {
                self.purge_password(PasswordType::Update);
            }
        }
        self.purge_sensitive_data();
    }
    pub fn resume(&mut self) {
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
                PasswordType::Update => self.update_password_policy = p,
            };
        } else {
            match pw_type {
                PasswordType::Boot => PasswordRetentionPolicy::AlwaysPurge,
                PasswordType::Update => PasswordRetentionPolicy::AlwaysPurge,
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
        // we change the salt ever-so-slightly for every password. This doesn't make any one password more secure;
        // but it disallows guessing all the passwords with a single off-the-shelf hashcat run.
        salt[0] ^= pw_type as u8;

        let timer = ticktimer_server::Ticktimer::new().expect("couldn't connect to ticktimer");
        // the bcrypt function takes the plaintext password and makes one copy to prime the blowfish bcrypt
        // cipher. It is responsible for erasing this state.
        let start_time = timer.elapsed_ms();
        bcrypt(BCRYPT_COST, &salt, pw, &mut hashed_password); // note: this internally makes a copy of the password, and destroys it
        let elapsed = timer.elapsed_ms() - start_time;
        log::info!("bcrypt cost: {} time: {}ms", BCRYPT_COST, elapsed); // benchmark to figure out how to set cost parameter

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
                PasswordType::Update => {
                    for (&src, dst) in digest.iter().zip((*pcache_ptr).hashed_update_pw.iter_mut()) {
                        *dst = src;
                    }
                    (*pcache_ptr).hashed_update_pw_valid = 1;
                }
            }
        }
    }

    /// Reads a 256-bit key at a given index offset
    fn read_key_256(&mut self, index: u8) -> [u8; 32] {
        let mut key: [u8; 32] = [0; 32];
        for (addr, word) in key.chunks_mut(4).into_iter().enumerate() {
            self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, index as u32 + addr as u32);
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
            self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, index as u32 + addr as u32);
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
    pub fn get_ux_password_type(&self) -> Option<PasswordType> {self.cur_password_type}

    pub fn is_initialized(&mut self) -> bool {
        self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, KeyRomLocs::CONFIG as u32);
        let config = self.keyrom.rf(utra::keyrom::DATA_DATA);
        if config & keyrom_config::INITIALIZED.ms(1) != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_pcache_update_password_valid(&self) -> bool {
        let pcache: &mut PasswordCache = unsafe{&mut *(self.pass_cache.as_mut_ptr() as *mut PasswordCache)};
        if pcache.hashed_update_pw_valid == 0 {
            false
        } else {
            true
        }
    }
    pub fn is_pcache_boot_password_valid(&self) -> bool {
        let pcache: &mut PasswordCache = unsafe{&mut *(self.pass_cache.as_mut_ptr() as *mut PasswordCache)};
        if pcache.hashed_boot_pw_valid == 0 {
            false
        } else {
            true
        }
    }

    /// Called by the UX layer to set up a key init run. It disables suspend/resume for the duration
    /// of the run, and also sets up some missing fields of KEYROM necessary to encrypt passwords.
    pub fn setup_key_init(&mut self) {
        unimplemented!();
    }

    #[allow(dead_code)]
    #[cfg(feature = "hazardous-debug")]
    pub fn printkeys(&mut self) {
        // dump the keystore -- used to confirm that patching worked right. does not get compiled in when hazardous-debug is not enable.
        for addr in 0..256 {
            self.keyrom.wfo(utra::keyrom::ADDRESS_ADDRESS, addr);
            self.sensitive_data.borrow_mut().as_slice_mut::<u32>()[addr as usize] = self.keyrom.rf(utra::keyrom::DATA_DATA);
            log::info!("{:02x}: 0x{:08x}", addr, self.sensitive_data.borrow_mut().as_slice::<u32>()[addr as usize]);
        }
    }


    #[cfg(feature = "hazardous-debug")]
    fn debug_staging(&self) {
        self.debug_print_key(KeyRomLocs::FPGA_KEY as usize, 256, "FPGA key: ");
        self.debug_print_key(KeyRomLocs::SELFSIGN_PRIVKEY as usize, 256, "Self private key: ");
        self.debug_print_key(KeyRomLocs::SELFSIGN_PUBKEY as usize, 256, "Self public key: ");
        self.debug_print_key(KeyRomLocs::DEVELOPER_PUBKEY as usize, 256, "Dev public key: ");
        self.debug_print_key(KeyRomLocs::THIRDPARTY_PUBKEY as usize, 256, "3rd party public key: ");
        self.debug_print_key(KeyRomLocs::USER_KEY as usize, 256, "Boot key: ");
        self.debug_print_key(KeyRomLocs::PEPPER as usize, 128, "Pepper: ");
        self.debug_print_key(KeyRomLocs::CONFIG as usize, 32, "Config (as BE): ");
        self.debug_print_key(KeyRomLocs::GLOBAL_ROLLBACK as usize, 32, "Global rollback state: ");
    }

    #[cfg(feature = "hazardous-debug")]
    fn debug_print_key(&self, offset: usize, num_bits: usize, name: &str) {
        use core::fmt::Write;
        let mut debugstr = xous_ipc::String::<4096>::new();
        write!(debugstr, "{}", name).unwrap();
        for word in self.sensitive_data.borrow_mut().as_slice::<u32>()[offset .. offset as usize + num_bits/(size_of::<u32>()*8)].iter() {
            for byte in word.to_be_bytes().iter() {
                write!(debugstr, "{:02x}", byte).unwrap();
            }
        }
        log::info!("{}", debugstr);
    }

    /// the public key must already be in the cache -- this version is used by the init routine, before the keys are written
    pub fn verify_selfsign_kernel(&mut self, is_system_initialized: bool) -> bool {
        unimplemented!();
    }

    pub fn sign_gateware(&self, signing_key: &Keypair) -> (Signature, u32) {
        unimplemented!();
    }

    /// This is a fast check on the gateware meant to be called on boot just to confirm that we're using a self-signed gateware
    pub fn verify_gateware_self_signature(&mut self) -> bool {
        unimplemented!();
    }

    /// This function does a comprehensive check of all the possible signature types in a specified gateware region
    pub fn check_gateware_signature(&mut self, region_enum: GatewareRegion) -> SignatureResult {
        unimplemented!();
    }

    pub fn fetch_gw_metadata(&self, region_enum: GatewareRegion) -> MetadataInFlash {
        let region = match region_enum {
            GatewareRegion::Boot => self.gateware(),
            GatewareRegion::Staging => self.staging(),
        };
        let md_ptr: *const MetadataInFlash =
            (&region[METADATA_OFFSET..METADATA_OFFSET + core::mem::size_of::<MetadataInFlash>()]).as_ptr() as *const MetadataInFlash;

        unsafe{*md_ptr}.clone()
    }

    pub fn commit_signature(&self, sig: Signature, len: u32, sig_type: SignatureType) -> Result<(), RootkeyResult> {
        unimplemented!()
    }

    /// Called by the UX layer at the epilogue of the initialization run. Allows suspend/resume to resume,
    /// and zero-izes any sensitive data that was created in the process.
    pub fn finish_key_init(&mut self) {
        // purge the password cache, if the policy calls for it
        match self.boot_password_policy {
            PasswordRetentionPolicy::AlwaysPurge => {
                self.purge_password(PasswordType::Boot);
            },
            _ => ()
        }
        match self.update_password_policy {
            PasswordRetentionPolicy::AlwaysPurge => {
                self.purge_password(PasswordType::Update);
            },
            _ => ()
        }

        // now purge the keyrom copy and other temporaries
        self.purge_sensitive_data();

        // re-allow suspend/resume ops
    }
}
