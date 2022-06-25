use crate::api::*;
use crate::implementation::bitflip;

use core::convert::TryInto;

use aes::Aes256;
use aes::cipher::{KeyInit, BlockDecrypt, BlockEncrypt};
use cipher::generic_array::GenericArray;

#[derive(Debug, Copy, Clone)]
pub enum FpgaKeySource {
    Bbram,
    Efuse,
}

pub(crate) const AES_BLOCKSIZE: usize = 16;
// a "slight" lie in that it's not literally the bitstream command, it's the fully encoded word + length of args.
pub(crate) const BITSTREAM_CTL0_CMD: u32       = 0x3000_a001;
pub(crate) const BITSTREAM_CTL0_CMD_FLIP: u32  = 0x8005_000c;
pub(crate) const BITSTREAM_MASK_CMD: u32       = 0x3000_c001;
#[allow(dead_code)]
pub(crate) const BITSTREAM_MASK_CMD_FLIP: u32  = 0x8005_000c;
pub(crate) const BITSTREAM_IV_CMD: u32         = 0x3001_6004;
pub(crate) const BITSTREAM_CIPHERTEXT_CMD: u32 = 0x3003_4001;
/// This structure encapsulates the tools necessary to create an Oracle that can go from
/// the encrypted bitstream to plaintext and back again, based on the position in the bitstream.
/// It is a partial re-implementation of the Cbc crate from block-ciphers, and the reason we're
/// not just using the stock Cbc crate is that it doesn't seem to support restarting the Cbc
/// stream from an arbitrary position.
pub(crate) struct BitstreamOracle<'a> {
    bitstream: &'a [u8],
    base: u32,
    dec_cipher: Aes256,
    enc_cipher: Aes256,
    iv: [u8; AES_BLOCKSIZE],
    /// subslice of the bitstream that contains just the encrypted area of the bitstream
    ciphertext: &'a [u8],
    ct_absolute_offset: usize,
    type2_count: u32,
    /// start of type2 data as an absolute offset in the overall bitstream
    type2_absolute_offset: usize,
    /// start of type2 data as an offset relative to the start of ciphertext
    type2_ciphertext_offset: usize,
    /// length of the undifferentiated plaintext header -- this is right up to the IV specifier
    #[allow(dead_code)]
    pt_header_len: usize,
    enc_to_key: FpgaKeySource,
    dec_from_key: FpgaKeySource,
}
impl<'a> BitstreamOracle<'a> {
    /// oracle supports separate encryption and decryption keys, so that it may
    /// be used for re-encryption of bitstreams to a new key. If using it for patching,
    /// set the keys to the same value.
    /// key_target selects what we want the encrypted target to be for boot key source; if None, we retain the bitstream settings
    pub fn new(dec_key: &'a[u8], enc_key: &'a[u8], bitstream: &'a[u8], base: u32) -> Result<BitstreamOracle<'a>, RootkeyResult> {
        let mut position: usize = 0;

        // Search through the bitstream for the key words that define the IV and ciphertext length.
        // This is done so that if extra headers are added or modified, the code doesn't break (versus coding in static offsets).
        let mut iv_pos = 0;
        let mut cwd = 0;
        while position < bitstream.len() {
            cwd = u32::from_be_bytes(bitstream[position..position+4].try_into().unwrap());
            if cwd == BITSTREAM_IV_CMD {
                iv_pos = position + 4
            }
            if cwd == BITSTREAM_CIPHERTEXT_CMD {
                break;
            }
            position += 1;
        }

        let position = position + 4;
        let ciphertext_len = 4 * u32::from_be_bytes(bitstream[position..position+4].try_into().unwrap());
        let ciphertext_start = position + 4;
        if ciphertext_start & (AES_BLOCKSIZE - 1) != 0 {
            log::error!("Padding is incorrect on the bitstream. Check append_csr.py for padding and make sure you are burning gateware with --raw-binary, and not --bitstream as the latter strips padding from the top of the file.");
            return Err(RootkeyResult::AlignmentError)
        }
        log::debug!("ciphertext len: {} bytes, start: 0x{:08x}", ciphertext_len, ciphertext_start);
        let ciphertext = &bitstream[ciphertext_start..ciphertext_start + ciphertext_len as usize];

        let mut iv_bytes: [u8; AES_BLOCKSIZE] = [0; AES_BLOCKSIZE];
        bitflip(&bitstream[iv_pos..iv_pos + AES_BLOCKSIZE], &mut iv_bytes);
        log::debug!("recovered iv (pre-flip): {:x?}", &bitstream[iv_pos..iv_pos + AES_BLOCKSIZE]);
        log::debug!("recovered iv           : {:x?}", &iv_bytes);

        let dec_cipher = Aes256::new(dec_key.try_into().unwrap());
        let enc_cipher = Aes256::new(enc_key.try_into().unwrap());

        let mut oracle = BitstreamOracle {
            bitstream,
            base,
            dec_cipher,
            enc_cipher,
            iv: iv_bytes,
            ciphertext,
            ct_absolute_offset: ciphertext_start,
            type2_count: 0,
            type2_absolute_offset: 0,
            type2_ciphertext_offset: 0,
            pt_header_len: iv_pos, // plaintext header goes all the way up to the IV
            enc_to_key: FpgaKeySource::Efuse, // these get set later
            dec_from_key: FpgaKeySource::Efuse,
        };

        // search forward for the "type 2" region in the first kilobyte of plaintext
        // type2 is where regular dataframes start, and we can compute offsets for patching
        // based on this.
        let mut first_block: [u8; 1024] = [0; 1024];
        oracle.decrypt(0, &mut first_block);

        // check that the plaintext header has a well-known sequence in it -- sanity check the AES key
        let mut pass = true;
        for &b in first_block[32..64].iter() {
            if b != 0x6C {
                pass = false;
            }
        }
        if !pass {
            log::error!("hmac_header did not decrypt correctly: {:x?}", &first_block[..64]);
            return Err(RootkeyResult::KeyError)
        }

        // start searching for the commands *after* the IV and well-known sequence
        let mut pt_pos = 64;
        let mut flipword: [u8; 4] = [0; 4];
        for word in first_block[64..].chunks_exact(4).into_iter() {
            bitflip(&word[0..4], &mut flipword);
            cwd = u32::from_be_bytes(flipword);
            pt_pos += 4;
            if (cwd & 0xE000_0000) == 0x4000_0000 {
                break;
            }
        }
        oracle.type2_count = cwd & 0x3FF_FFFF;
        if pt_pos > 1000 { // pt_pos is usually found within the first 200 bytes of a bitstream, should definitely be in the first 1k or else shenanigans
            log::error!("type 2 region not found in the expected region, is the FPGA key correct?");
            return Err(RootkeyResult::KeyError)
        }
        oracle.type2_absolute_offset = pt_pos + ciphertext_start;
        oracle.type2_ciphertext_offset = pt_pos;
        log::debug!("type2 absolute: {}, relative to ct start: {}", oracle.type2_absolute_offset, oracle.type2_ciphertext_offset);

        // read the boot source out of the ciphertext
        let mut bytes = first_block.chunks(4).into_iter();
        let mut ctl0_enc: Option<u32> = None;
        loop {
            if let Some(b) = bytes.next() {
                let word = u32::from_be_bytes(b.try_into().unwrap());
                if word == BITSTREAM_CTL0_CMD_FLIP {
                    if let Some(val) = bytes.next() {
                        let mut flip: [u8; 4] = [0; 4];
                        bitflip(val, &mut flip);
                        let w = u32::from_be_bytes(flip.try_into().unwrap());
                        ctl0_enc = Some(w);
                    } else {
                        log::error!("didn't decrypt enough memory to find the ctl0 encrypted settings");
                        return Err(RootkeyResult::IntegrityError);
                    }
                    break;
                }
            } else {
                break;
            }
        }
        if (ctl0_enc.unwrap() & 0x8000_0000) == 0x8000_0000 {
            oracle.dec_from_key = FpgaKeySource::Efuse;
        } else {
            oracle.dec_from_key = FpgaKeySource::Bbram;
        }
        // by default, we always re-encrypt to the same key type
        oracle.enc_to_key = oracle.dec_from_key;

        Ok(oracle)
    }

    #[allow(dead_code)]
    pub fn pt_header_len(&self) -> usize {self.pt_header_len as usize}
    pub fn base(&self) -> u32 {self.base}
    pub fn bitstream(&self) -> &[u8] { self.bitstream }
    pub fn ciphertext_offset(&self) -> usize {
        self.ct_absolute_offset as usize
    }
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
    pub fn get_original_key_type(&self) -> FpgaKeySource {self.dec_from_key}
    pub fn get_target_key_type(&self) -> FpgaKeySource {self.enc_to_key}
    pub fn set_target_key_type(&mut self, keytype: FpgaKeySource) {
        self.enc_to_key = keytype;
    }
    pub fn ciphertext_offset_to_frame(&self, offset: usize) -> (usize, usize) {
        let type2_offset = offset - self.type2_ciphertext_offset;

        let frame = type2_offset / (101 * 4);
        let frame_offset = type2_offset - (frame * 101 * 4);
        (frame, frame_offset / 4)
    }
    pub fn clear(&mut self) {
        self.enc_cipher.clear();
        self.dec_cipher.clear();

        for b in self.iv.iter_mut() {
            *b = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    /// Decrypts a portion of the bitstream starting at "from", of length output.
    /// Returns the actual number of bytes processed.
    pub fn decrypt(&self, from: usize, output: &mut [u8]) -> usize {
        assert!(from & (AES_BLOCKSIZE - 1) == 0); // all requests must be an even multiple of an AES block size

        let mut index = from;
        let mut temp_block = [0; AES_BLOCKSIZE];
        let mut chain: [u8; AES_BLOCKSIZE] = [0; AES_BLOCKSIZE];
        let mut bytes_processed = 0;
        for block in output.chunks_mut(AES_BLOCKSIZE).into_iter() {
            if index > self.ciphertext_len() - AES_BLOCKSIZE {
                return bytes_processed;
            }
            if index ==  0 {
                chain = self.iv;
            } else {
                bitflip(&self.ciphertext[index - AES_BLOCKSIZE..index], &mut chain);
            };
            // copy the ciphertext into the temp_block, with a bitflip
            bitflip(&self.ciphertext[index..index + AES_BLOCKSIZE], &mut temp_block);

            // replaces the ciphertext with "plaintext"
            let mut d = GenericArray::clone_from_slice(&mut temp_block);
            self.dec_cipher.decrypt_block(&mut d);
            for (&src, dst) in d.iter().zip(temp_block.iter_mut()) {
                *dst = src;
            }

            // now XOR against the IV into the final output block. We use a "temp" block so we
            // guarantee an even block size for AES, but in fact, the output block does not
            // have to be an even multiple of our block size!
            for (dst, (&src, &iv)) in block.iter_mut().zip(temp_block.iter().zip(chain.iter())) {
                *dst = src ^ iv;
            }
            index += AES_BLOCKSIZE;
            bytes_processed += AES_BLOCKSIZE;
        }
        bytes_processed
    }

    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}
