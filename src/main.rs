#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

pub(crate) const SERVER_NAME_SPINOR: &str = "_SPINOR Hardware Interface Server_";

mod api;
use api::*;
use xous::msg_blocking_scalar_unpack;

use num_traits::*;

use std::str;

mod other_fake_servers;

#[cfg(any(target_os = "none", target_os = "xous"))]
mod implementation;
#[cfg(any(target_os = "none", target_os = "xous"))]
use implementation::*;

#[cfg(any(target_os = "none", target_os = "xous"))]
mod bcrypt;

pub enum SignatureResult {
    SelfSignOk,
    ThirdPartyOk,
    DevKeyOk,
    Invalid,
}
#[allow(dead_code)]
pub enum GatewareRegion {
    Boot,
    Staging,
}

/// An "easily" parseable metadata structure in flash. There's nothing that guarantees the authenticity
/// of the metadata in and of itself, other than the digital signature that wraps the entire gateware record.
/// Thus we're relying on the person who signs the gateware to not inject false data here.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct MetadataInFlash {
    pub magic: u32, // 0x6174656d 'atem'
    pub version: u32,
    /// git data, but formatted as binary integers
    pub git_additional: u32, // commits beyond the tag
    pub git_rev: u32,
    pub git_min: u32,
    pub git_maj: u32,
    pub git_commit: u32,
    /// md5sum of the dummy-encrypted source file; not meant to be secure, just for human-ID purposes
    pub bin_checksum: [u8; 16],
    /// md5sum of 'betrusted_soc.py'
    pub src_checksum: [u8; 16],
    /// date as free-form string (for human readable purposes)
    pub date_len: u32,
    pub date_str: [u8; 64],
    /// the host on which the image was built
    pub host_len: u32,
    pub host_str: [u8; 64],
    /// git tag info as a free-form string
    pub tag_len: u32,
    pub tag_str: [u8; 64],
    /// git log info of the last commit, as a free-form string.
    pub log_len: u32,
    pub log_str: [u8; 512],
    /// status of the build tree, as a free-form string.
    pub status_len: u32,
    pub status_str: [u8; 1024],
}

struct XousLogger;
static XOUS_LOGGER: XousLogger = XousLogger {};

impl log::Log for XousLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!(
            "{}:{}: {} ({}:{})",
            record.level(),
            record.target(),
            record.args(),
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0)
        );
    }

    fn flush(&self) {}
}

fn main() -> ! {
    log::set_logger(&XOUS_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    log::info!("my PID is {}", xous::process::id());

    other_fake_servers::start();

    run_fake_root_keys();
}

fn run_fake_root_keys() -> ! {
    log::set_max_level(log::LevelFilter::Trace);
    let xns = xous_names::XousNames::new().unwrap();
    /*
       Connections allowed to the keys server:
          0. Password entry UX thread (self, created without xns)
          0. Key purge timer (self, created without xns)
          1. Shellchat for test initiation
          2. Main menu -> trigger initialization
          3. PDDB
    */
    let keys_sid = xns
        .register_name(api::SERVER_NAME_KEYS, Some(3))
        .expect("can't register server");

    let mut keys = RootKeys::new();
    log::info!("Boot FPGA key source: {:?}", keys.fpga_key_source());

    keys.set_ux_password_type(Some(PasswordType::Boot));
    let default_password = "a";
    println!(">>> Using return password: \"{}\"", default_password);
    keys.hash_and_save_password(default_password);
    keys.update_policy(Some(PasswordRetentionPolicy::EraseOnSuspend));

    // Register a fake SoC token. This is required in order to allow the spinor server
    // to write to flash.
    let spinor_connection = xns
        .request_connection_blocking(SERVER_NAME_SPINOR)
        .expect("Can't connect to Spinor server");
    xous::send_message(
        spinor_connection,
        xous::Message::new_scalar(2 /* RegisterSocToken */, 1, 2, 3, 4),
    )
    .expect("couldn't register fake token");
    log::trace!("registered fake soc token with spinor server");

    log::trace!("ready to accept requests");

    let mut aes_sender: Option<xous::MessageSender> = None;
    loop {
        let mut msg = xous::receive_message(keys_sid).unwrap();
        let opcode = FromPrimitive::from_usize(msg.body.id()).unwrap_or(Opcode::InvalidOpcode);
        log::debug!(
            "fake rootkeys message: opcode {:#?} {:x?}",
            opcode,
            msg.body
        );
        match opcode {
            Opcode::SuspendResume => {}
            Opcode::KeysInitialized => {
                if keys.is_initialized() {
                    xous::return_scalar(msg.sender, 1).unwrap();
                } else {
                    xous::return_scalar(msg.sender, 0).unwrap();
                }
            }
            Opcode::IsEfuseSecured => {
                if let Some(secured) = keys.is_efuse_secured() {
                    if secured {
                        xous::return_scalar(msg.sender, 1).unwrap();
                    } else {
                        xous::return_scalar(msg.sender, 0).unwrap();
                    }
                } else {
                    xous::return_scalar(msg.sender, 2).unwrap();
                }
            }
            Opcode::IsJtagWorking => {
                if keys.is_jtag_working() {
                    xous::return_scalar(msg.sender, 1).unwrap();
                } else {
                    xous::return_scalar(msg.sender, 0).unwrap();
                }
            }
            Opcode::ClearPasswordCacheEntry => {
                msg_blocking_scalar_unpack!(msg, pass_type_code, _, _, _, {
                    let pass_type: AesRootkeyType = FromPrimitive::from_usize(pass_type_code)
                        .unwrap_or(AesRootkeyType::NoneSpecified);
                    keys.purge_user_password(pass_type);
                    xous::return_scalar(msg.sender, 1).unwrap();
                })
            }

            // UX flow opcodes
            Opcode::UxTryInitKeys => unimplemented!(),
            Opcode::UxInitBootPasswordReturn => {
                unimplemented!()
            }
            Opcode::InitBootPassword => {
                // Only operate on memory messages
                if !msg.body.has_memory() {
                    if msg.body.is_blocking() {
                        xous::return_scalar(msg.sender, 0).unwrap();
                    }
                    continue;
                }
                let mem = msg.body.memory_message().unwrap();
                keys.set_ux_password_type(Some(PasswordType::Boot));
                let s = {
                    let len = mem.valid.map(|v| v.get()).unwrap_or(mem.buf.len());
                    let slice = unsafe { core::slice::from_raw_parts(mem.buf.as_ptr(), len) };
                    match core::str::from_utf8(slice) {
                        Err(_) => {
                            log::error!("password was not valid UTF-8");
                            continue;
                        }
                        Ok(o) => o,
                    }
                };
                println!(">>> Using return password: \"{}\"", s);
                keys.hash_and_save_password(s);
                keys.update_policy(Some(PasswordRetentionPolicy::EraseOnSuspend));
            }
            Opcode::UxInitUpdatePasswordReturn => {
                unimplemented!()
            }
            Opcode::UxTryReboot => {
                unimplemented!()
            }
            Opcode::UxDoReboot => {
                unimplemented!()
            }
            Opcode::UxUpdateGateware => {
                unimplemented!()
            }
            Opcode::UxUpdateGwPasswordReturn => {
                unimplemented!()
            }
            Opcode::UxUpdateGwRun => {
                unimplemented!()
            }
            Opcode::UxSelfSignXous => {
                unimplemented!()
            }
            Opcode::UxSignXousPasswordReturn => {
                unimplemented!()
            }
            Opcode::UxSignXousRun => {
                unimplemented!()
            }
            Opcode::UxAesEnsurePassword => {
                msg_blocking_scalar_unpack!(msg, key_index, _, _, _, {
                    if key_index as u8 == AesRootkeyType::User0.to_u8().unwrap() {
                        if keys.is_pcache_boot_password_valid() {
                            // short circuit the process if the cache is hot
                            log::info!("Boot password already valid");
                            xous::return_scalar(msg.sender, 1).unwrap();
                            continue;
                        }
                        if aes_sender.is_some() {
                            log::error!(
                                "multiple concurrent requests to UxAesEnsurePasword, not allowed!"
                            );
                            xous::return_scalar(msg.sender, 0).unwrap();
                        } else {
                            aes_sender = Some(msg.sender);
                        }
                        keys.set_ux_password_type(Some(PasswordType::Boot));
                        log::info!("Asking the user for their boot password");
                        // //password_action.set_action_opcode(Opcode::UxAesPasswordPolicy.to_u32().unwrap()); // skip policy question. it's annoying.
                        // password_action
                        //     .set_action_opcode(Opcode::UxAesEnsureReturn.to_u32().unwrap());
                        // rootkeys_modal.modify(
                        //     Some(ActionType::TextEntry(password_action.clone())),
                        //     Some(t!("rootkeys.get_login_password", xous::LANG)),
                        //     false,
                        //     None,
                        //     true,
                        //     None,
                        // );
                        log::info!(
                            "{}ROOTKEY.BOOTPW,{}",
                            xous::BOOKEND_START,
                            xous::BOOKEND_END
                        );
                        // rootkeys_modal.activate();
                        // note that the scalar is *not* yet returned, it will be returned by the opcode called by the password assurance
                    } else {
                        // insert other indices, as we come to have them in else-ifs
                        // note that there needs to be a way to keep the ensured password in sync with the
                        // actual key index (if multiple passwords are used/required). For now, because there is only
                        // one password, we can use is_pcache_boot_password_valid() to sync that up; but as we add
                        // more keys with more passwords, this policy may need to become markedly more complicated!

                        // otherwise, an invalid password request
                        log::error!("bad_password_request");
                        xous::return_scalar(msg.sender, 0).unwrap();
                    }
                })
            }
            Opcode::UxAesPasswordPolicy => {
                unimplemented!()
            }
            Opcode::UxAesEnsureReturn => {
                unimplemented!()
            }
            Opcode::AesOracle => {
                unimplemented!()
            }
            Opcode::AesKwp => {
                let mut buffer = unsafe {
                    xous_ipc::Buffer::from_memory_message_mut(
                        msg.body.memory_message_mut().unwrap(),
                    )
                };
                let mut kwp = buffer.to_original::<KeyWrapper, _>().unwrap();
                keys.kwp_op(&mut kwp);
                buffer.replace(kwp).unwrap();
            }

            Opcode::BbramProvision => {
                unimplemented!()
            }
            Opcode::UxBbramCheckReturn => {
                unimplemented!()
            }
            Opcode::UxBbramPasswordReturn => {
                unimplemented!()
            }
            Opcode::UxBbramRun => {
                unimplemented!()
            }

            Opcode::CheckGatewareSignature => {
                msg_blocking_scalar_unpack!(msg, _, _, _, _, { unimplemented!() })
            }
            Opcode::TestUx => msg_blocking_scalar_unpack!(msg, _arg, _, _, _, {
                // dummy test for now
                xous::return_scalar(msg.sender, 1234).unwrap();
            }),
            Opcode::UxGutter => {
                // an intentional NOP for UX actions that require a destintation but need no action
            }

            // boilerplate Ux handlers
            Opcode::ModalRedraw => {
                unimplemented!()
            }
            Opcode::ModalKeys => unimplemented!(),
            Opcode::ModalDrop => {
                panic!("Password modal for rootkeys quit unexpectedly")
            }
            Opcode::Quit => {
                log::warn!("password thread received quit, exiting.");
                break;
            }
            Opcode::InvalidOpcode => {
                log::error!("couldn't convert opcode");
            }
        }
    }
    // clean up our program
    log::trace!("main loop exit, destroying servers");
    xns.unregister_server(keys_sid).unwrap();
    xous::destroy_server(keys_sid).unwrap();
    log::trace!("quitting");
    xous::terminate_process(0)
}
