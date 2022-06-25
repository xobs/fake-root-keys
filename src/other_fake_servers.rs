const SERVER_NAME_MODALS: &'static str = "_Modal Dialog Server_";
const TIME_SERVER_PDDB: &'static str = "_dedicated pddb timeserver connection_";
const SERVER_NAME_GAM: &'static str = "_Graphical Abstraction Manager_";
const SERVER_NAME_GFX: &'static str = "_Graphics_";

/// PDDB requires this in order to reset time.
fn fake_time_server() {
    let xns = xous_names::XousNames::new().unwrap();
    log::debug!("Creating fake time server");
    let priv_sid = xns
        .register_name(TIME_SERVER_PDDB, Some(1))
        .expect("can't register server");

    loop {
        let msg = xous::receive_message(priv_sid).unwrap();
        log::debug!(
            "Got a message with ID {} on the private time server: {:x?}",
            msg.id(),
            msg.body
        );
        if msg.body.is_blocking() && !msg.body.has_memory() {
            xous::return_scalar(msg.sender, 0).unwrap();
        }
    }
}

fn fake_modals_server() {
    let xns = xous_names::XousNames::new().unwrap();
    log::debug!("Creating fake modals server");
    let priv_sid = xns
        .register_name(SERVER_NAME_MODALS, None)
        .expect("can't register server");

    loop {
        let mut msg = xous::receive_message(priv_sid).unwrap();
        log::debug!(
            "Got a message with ID {} on the modals server: {:x?}",
            msg.id(),
            msg.body
        );

        // PromptWithFixedResponse
        if msg.id() == 0 {
            if let Some(msg) = msg.body.memory_message_mut() {
                let mutable_vec: &mut [u8] = msg.buf.as_slice_mut();
                let mut i = mutable_vec.iter_mut();
                msg.offset = None;

                // Indicates this is a discriminant 0 -- `SetCanvasBoundsReturn(SetCanvasBoundsRequest)`
                *i.next().unwrap() = 2;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
            }
        }

        // GetMutex
        if msg.id() == 15 && msg.body.is_blocking() && !msg.body.has_memory() {
            xous::return_scalar(msg.sender, 1).unwrap();
            continue;
        }

        if msg.body.is_blocking() && !msg.body.has_memory() {
            xous::return_scalar(msg.sender, 0).unwrap();
        }
    }
}

fn fake_gfx_server() {
    let xns = xous_names::XousNames::new().unwrap();
    log::debug!("Creating fake modals server");
    let priv_sid = xns
        .register_name(SERVER_NAME_GFX, None)
        .expect("can't register server");

    loop {
        let msg = xous::receive_message(priv_sid).unwrap();
        log::debug!(
            "Got a message with ID {} on the modals server: {:x?}",
            msg.id(),
            msg.body
        );
        if msg.body.is_blocking() && !msg.body.has_memory() {
            xous::return_scalar(msg.sender, 0).unwrap();
        }
    }
}

fn fake_gam_server() {
    let xns = xous_names::XousNames::new().unwrap();
    log::debug!("Creating fake GAM server");
    let priv_sid = xns
        .register_name(SERVER_NAME_GAM, None)
        .expect("can't register server");

    loop {
        let mut msg = xous::receive_message(priv_sid).unwrap();
        log::debug!(
            "Got a message with ID {} on the GAM server: {:x?}",
            msg.id(),
            msg.body
        );

        // GetCanvasBounds
        if msg.id() == 1 && msg.body.is_blocking() && !msg.body.has_memory() {
            xous::return_scalar2(msg.sender, 0x0000_0000, 0x0100_0100).unwrap();
            continue;
        }

        // SetCanvasBounds
        if msg.id() == 2 {
            if let Some(msg) = msg.body.memory_message_mut() {
                let mutable_vec: &mut [u8] = msg.buf.as_slice_mut();
                let mut i = mutable_vec.iter_mut();
                msg.offset = None;

                // Indicates this is a discriminant 0 -- `SetCanvasBoundsReturn(SetCanvasBoundsRequest)`
                *i.next().unwrap() = 2;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Actual contents, token (should be equal to the previous contents)
                *i.next().unwrap() = 1;
                *i.next().unwrap() = 2;
                *i.next().unwrap() = 3;
                *i.next().unwrap() = 4;

                // Token Type (Gam)
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Requested (point)
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Option<Point>
                *i.next().unwrap() = 1;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Contents of Option<Point>
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
            }
        }

        // RenderTextView
        if msg.id() == 6 {
            if let Some(msg) = msg.body.memory_message_mut() {
                let mutable_vec: &mut [u8] = msg.buf.as_slice_mut();

                // It's a big struct. Zero it out.
                for i in mutable_vec.iter_mut() {
                    *i = 0;
                }

                let mut i = mutable_vec.iter_mut();
                msg.offset = None;

                // Indicates this is a discriminant 1 -- `RenderReturn(TextView)`
                *i.next().unwrap() = 1;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
            }
        }
        // RegisterUx
        if msg.id() == 9 {
            if let Some(msg) = msg.body.memory_message_mut() {
                let mutable_vec: &mut [u8] = msg.buf.as_slice_mut();
                let mut i = mutable_vec.iter_mut();
                msg.offset = None;

                // Indicates this is a discriminant 0 -- `UxToken(Option<[u32; 4]>)`
                *i.next().unwrap() = 0;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Option<T> field. `1` indicates `Some(T)`.
                *i.next().unwrap() = 1;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Actual contents, word 1
                *i.next().unwrap() = 1;
                *i.next().unwrap() = 2;
                *i.next().unwrap() = 3;
                *i.next().unwrap() = 4;

                // Actual contents, word 2
                *i.next().unwrap() = 5;
                *i.next().unwrap() = 6;
                *i.next().unwrap() = 7;
                *i.next().unwrap() = 8;

                // Actual contents, word 3
                *i.next().unwrap() = 9;
                *i.next().unwrap() = 10;
                *i.next().unwrap() = 11;
                *i.next().unwrap() = 12;

                // Actual contents, word 4
                *i.next().unwrap() = 13;
                *i.next().unwrap() = 14;
                *i.next().unwrap() = 15;
                *i.next().unwrap() = 16;
            }
        }

        // RequestContentCanvas
        if msg.id() == 8 {
            if let Some(msg) = msg.body.memory_message_mut() {
                let mutable_vec: &mut [u8] = msg.buf.as_slice_mut();
                let mut i = mutable_vec.iter_mut();
                msg.offset = None;

                // Indicates this is a discriminant 3 -- `ContentCanvasReturn(Option<Gid>)`
                *i.next().unwrap() = 3;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Option<T> field. `1` indicates `Some(T)`.
                *i.next().unwrap() = 1;
                // Next three bytes are padding
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;
                *i.next().unwrap() = 0;

                // Actual contents, word 1
                *i.next().unwrap() = 1;
                *i.next().unwrap() = 2;
                *i.next().unwrap() = 3;
                *i.next().unwrap() = 4;

                // Actual contents, word 2
                *i.next().unwrap() = 5;
                *i.next().unwrap() = 6;
                *i.next().unwrap() = 7;
                *i.next().unwrap() = 8;

                // Actual contents, word 3
                *i.next().unwrap() = 9;
                *i.next().unwrap() = 10;
                *i.next().unwrap() = 11;
                *i.next().unwrap() = 12;

                // Actual contents, word 4
                *i.next().unwrap() = 13;
                *i.next().unwrap() = 14;
                *i.next().unwrap() = 15;
                *i.next().unwrap() = 16;
            }
        }

        if msg.body.is_blocking() && !msg.body.has_memory() {
            xous::return_scalar(msg.sender, 0).unwrap();
        }
    }
}

pub fn start() {
    std::thread::spawn(fake_time_server);
    std::thread::spawn(fake_modals_server);
    std::thread::spawn(fake_gfx_server);
    std::thread::spawn(fake_gam_server);
}
