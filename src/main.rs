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
                // // assume:
                // //   - setup_key_init has also been called (exactly once, before anything happens)
                // //   - set_ux_password_type has been called already
                // let mut buf =
                //     unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                // let plaintext_pw = buf
                //     .to_original::<gam::modal::TextEntryPayloads, _>()
                //     .unwrap();

                // keys.hash_and_save_password(plaintext_pw.first().as_str());
                // plaintext_pw.first().volatile_clear(); // ensure the data is destroyed after sending to the keys enclave
                // buf.volatile_clear();

                // keys.set_ux_password_type(Some(PasswordType::Update));
                // // pop up our private password dialog box
                // password_action
                //     .set_action_opcode(Opcode::UxInitUpdatePasswordReturn.to_u32().unwrap());
                // rootkeys_modal.modify(
                //     Some(ActionType::TextEntry(password_action.clone())),
                //     Some(t!("rootkeys.updatepass", xous::LANG)),
                //     false,
                //     None,
                //     true,
                //     None,
                // );
                // #[cfg(feature = "tts")]
                // tts.tts_blocking(t!("rootkeys.updatepass", xous::LANG))
                //     .unwrap();
                // log::info!("{}ROOTKEY.UPDPW,{}", xous::BOOKEND_START, xous::BOOKEND_END);
                // rootkeys_modal.activate();
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
                // let mut buf =
                //     unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                // let plaintext_pw = buf
                //     .to_original::<gam::modal::TextEntryPayloads, _>()
                //     .unwrap();

                // keys.hash_and_save_password(plaintext_pw.first().as_str());
                // plaintext_pw.first().volatile_clear(); // ensure the data is destroyed after sending to the keys enclave
                // buf.volatile_clear();

                // keys.set_ux_password_type(None);

                // // this routine will update the rootkeys_modal with the current Ux state
                // let result = keys.do_key_init(&mut rootkeys_modal, main_cid);
                // // the stop emoji, when sent to the slider action bar in progress mode, will cause it to close and relinquish focus
                // rootkeys_modal.key_event(['🛑', '\u{0000}', '\u{0000}', '\u{0000}']);

                // log::info!("set_ux_password result: {:?}", result);

                // // clear all the state, re-enable suspend/resume
                // keys.finish_key_init();

                // match result {
                //     Ok(_) => {
                //         log::info!("going to into reboot arc");
                //         send_message(
                //             main_cid,
                //             xous::Message::new_scalar(
                //                 Opcode::UxTryReboot.to_usize().unwrap(),
                //                 0,
                //                 0,
                //                 0,
                //                 0,
                //             ),
                //         )
                //         .expect("couldn't initiate dialog box");
                //     }
                //     Err(RootkeyResult::AlignmentError) => {
                //         modals
                //             .get()
                //             .show_notification(t!("rootkeys.init.fail_alignment", xous::LANG), None)
                //             .expect("modals error");
                //     }
                //     Err(RootkeyResult::KeyError) => {
                //         modals
                //             .get()
                //             .show_notification(t!("rootkeys.init.fail_key", xous::LANG), None)
                //             .expect("modals error");
                //     }
                //     Err(RootkeyResult::IntegrityError) => {
                //         modals
                //             .get()
                //             .show_notification(t!("rootkeys.init.fail_verify", xous::LANG), None)
                //             .expect("modals error");
                //     }
                //     Err(RootkeyResult::FlashError) => {
                //         modals
                //             .get()
                //             .show_notification(t!("rootkeys.init.fail_burn", xous::LANG), None)
                //             .expect("modals error");
                //     }
                // }
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
                // let mut buf =
                //     unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                // let plaintext_pw = buf
                //     .to_original::<gam::modal::TextEntryPayloads, _>()
                //     .unwrap();

                // keys.hash_and_save_password(plaintext_pw.first().as_str());
                // plaintext_pw.first().volatile_clear(); // ensure the data is destroyed after sending to the keys enclave
                // buf.volatile_clear();
                // // indicate that there should be no change to the policy
                // let payload =
                //     gam::RadioButtonPayload::new(t!("rootkeys.policy_suspend", xous::LANG));
                // let buf = Buffer::into_buf(payload).expect("couldn't convert message to payload");
                // buf.send(main_cid, Opcode::UxUpdateGwRun.to_u32().unwrap())
                //     .map(|_| ())
                //     .expect("couldn't send action message");
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
                // // this is bypassed, it's not useful. You basically always only want to retain the password until sleep.
                // let mut buf =
                //     unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                // let plaintext_pw = buf
                //     .to_original::<gam::modal::TextEntryPayloads, _>()
                //     .unwrap();

                // keys.hash_and_save_password(plaintext_pw.first().as_str());
                // plaintext_pw.first().volatile_clear(); // ensure the data is destroyed after sending to the keys enclave
                // buf.volatile_clear();

                // let mut confirm_radiobox = gam::modal::RadioButtons::new(
                //     main_cid,
                //     Opcode::UxAesEnsureReturn.to_u32().unwrap(),
                // );
                // confirm_radiobox.is_password = true;
                // confirm_radiobox.add_item(ItemName::new(t!("rootkeys.policy_suspend", xous::LANG)));
                // // confirm_radiobox.add_item(ItemName::new(t!("rootkeys.policy_clear", xous::LANG))); // this policy makes no sense in the use case of the key
                // confirm_radiobox.add_item(ItemName::new(t!("rootkeys.policy_keep", xous::LANG)));
                // rootkeys_modal.modify(
                //     Some(ActionType::RadioButtons(confirm_radiobox)),
                //     Some(t!("rootkeys.policy_request", xous::LANG)),
                //     false,
                //     None,
                //     true,
                //     None,
                // );
                // #[cfg(feature = "tts")]
                // tts.tts_blocking(t!("rootkeys.policy_request", xous::LANG))
                //     .unwrap();
                // rootkeys_modal.activate();
            }
            Opcode::UxAesEnsureReturn => {
                // if let Some(sender) = aes_sender.take() {
                //     xous::return_scalar(sender, 1).unwrap();
                //     {
                //         let mut buf = unsafe {
                //             Buffer::from_memory_message(msg.body.memory_message().unwrap())
                //         };
                //         let plaintext_pw = buf
                //             .to_original::<gam::modal::TextEntryPayloads, _>()
                //             .unwrap();
                //         keys.hash_and_save_password(plaintext_pw.first().as_str());
                //         plaintext_pw.first().volatile_clear(); // ensure the data is destroyed after sending to the keys enclave
                //         buf.volatile_clear();

                //         // this is a reasonable default policy -- don't bother the user to answer this question all the time.
                //         keys.update_policy(Some(PasswordRetentionPolicy::EraseOnSuspend));
                //     }

                //     keys.set_ux_password_type(None);
                // } else {
                //     xous::return_scalar(msg.sender, 0).unwrap();
                //     log::warn!("UxAesEnsureReturn detected a fat-finger event. Ignoring.");
                // }
            }
            Opcode::AesOracle => {
                // let mut buffer = unsafe {
                //     Buffer::from_memory_message_mut(msg.body.memory_message_mut().unwrap())
                // };
                // // as_flat saves a copy step, but we have to deserialize some enums manually
                // let mut aes_op = buffer.to_original::<AesOp, _>().unwrap();
                // let op = match aes_op.aes_op {
                //     // seems stupid, but we have to do this because we want to have zeroize on the AesOp record, and it means we can't have Copy on this.
                //     AesOpType::Decrypt => AesOpType::Decrypt,
                //     AesOpType::Encrypt => AesOpType::Encrypt,
                // };
                // // deserialize the specifier
                // match aes_op.block {
                //     AesBlockType::SingleBlock(mut b) => {
                //         keys.aes_op(aes_op.key_index, op, &mut b);
                //         aes_op.block = AesBlockType::SingleBlock(b);
                //     }
                //     AesBlockType::ParBlock(mut pb) => {
                //         keys.aes_par_op(aes_op.key_index, op, &mut pb);
                //         aes_op.block = AesBlockType::ParBlock(pb);
                //     }
                // };
                // buffer.replace(aes_op).unwrap();
            }
            Opcode::AesKwp => {
                let mut buffer = unsafe {
                    xous_ipc::Buffer::from_memory_message_mut(
                        msg.body.memory_message_mut().unwrap(),
                    )
                };
                let mut kwp = buffer.to_original::<KeyWrapper, _>().unwrap();
                // println!("kwp: {:?}", kwp);
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
