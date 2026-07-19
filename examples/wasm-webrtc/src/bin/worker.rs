//! Web worker running the sframe Encoded Transforms off the main thread.
//!
//! `RTCRtpScriptTransform` requires a worker: the browser fires an
//! `rtctransform` event here with the frame streams to pipe through. One event
//! fires per attached transform (one encrypt, one decrypt in this demo).
//!
//! The codecs live in worker-global state keyed by operation so a `postMessage`
//! from the app can re-derive their keys live (the "update passphrases" button).

use std::cell::RefCell;
use std::collections::HashMap;

use js_sys::{Object, Reflect, Uint8Array};
use sframe_wasm_webrtc::transform::{Receiver, Sender, decrypt_vp8, encrypt_vp8};
use wasm_bindgen::prelude::*;
use web_sys::{
    DedicatedWorkerGlobalScope, MessageEvent, ReadableWritablePair, RtcEncodedVideoFrame,
    RtcTransformEvent, TransformStream, TransformStreamDefaultController,
};

thread_local! {
    /// The live codecs, keyed by operation ("encrypt" / "decrypt").
    static CODECS: RefCell<HashMap<String, KeyedCodec>> = RefCell::new(HashMap::new());
}

fn main() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).ok();
    log::info!("worker started");

    let global: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();

    let on_transform = Closure::<dyn FnMut(RtcTransformEvent)>::new(|event: RtcTransformEvent| {
        log::info!("rtctransform event");
        if let Err(err) = wire_up(event) {
            log::error!("wire_up failed: {err:?}");
        }
    });
    // web-sys has no typed setter for onrtctransform yet.
    let _ = Reflect::set(&global, &"onrtctransform".into(), on_transform.as_ref());
    on_transform.forget();

    // The app posts { sendPass, recvPass } to re-key the live codecs.
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(|event: MessageEvent| {
        let data = event.data();
        if let Ok(send_pass) = string_field(&data, "sendPass") {
            rekey("encrypt", &send_pass);
        }
        if let Ok(recv_pass) = string_field(&data, "recvPass") {
            rekey("decrypt", &recv_pass);
        }
    });
    global.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
}

/// Either direction of the frame codec, plus the key id needed to re-derive it.
struct KeyedCodec {
    key_id: u64,
    codec: Codec,
}

enum Codec {
    Encrypt(Sender),
    Decrypt(Receiver),
}

impl Codec {
    fn process(&mut self, frame: &[u8]) -> sframe::error::Result<Vec<u8>> {
        match self {
            Codec::Encrypt(sender) => encrypt_vp8(sender, frame).map(<[u8]>::to_vec),
            Codec::Decrypt(receiver) => decrypt_vp8(receiver, frame).map(<[u8]>::to_vec),
        }
    }
}

/// The log prefix for a transform operation.
fn role_of(operation: &str) -> &'static str {
    if operation == "encrypt" { "sender" } else { "receiver" }
}

/// Re-derives one direction's key from a new passphrase, in place.
fn rekey(operation: &str, passphrase: &str) {
    CODECS.with(|codecs| {
        let mut codecs = codecs.borrow_mut();
        let Some(entry) = codecs.get_mut(operation) else {
            return;
        };
        let result = match &mut entry.codec {
            Codec::Encrypt(sender) => sender.set_encryption_key(passphrase),
            Codec::Decrypt(receiver) => receiver.set_encryption_key(entry.key_id, passphrase),
        };
        match result {
            Ok(()) => log::info!("[{}] re-keyed", role_of(operation)),
            Err(err) => log::warn!("[{}] re-key failed: {err}", role_of(operation)),
        }
    });
}

/// The transform's setup, parsed out of the JS options object.
struct TransformConfig {
    operation: String,
    key_id: u64,
    passphrase: String,
}

/// Builds the codec from the transform's options and pipes its frames through it.
fn wire_up(event: RtcTransformEvent) -> Result<(), JsValue> {
    let transformer = event.transformer();
    let config = read_config(&transformer.options())?;
    let role = role_of(&config.operation);

    let codec = build_codec(&config)?;
    CODECS.with(|codecs| {
        codecs.borrow_mut().insert(
            config.operation.clone(),
            KeyedCodec { key_id: config.key_id, codec },
        )
    });
    log::info!("[{role}] wired up (keyId {}, {} char key)", config.key_id, config.passphrase.len());

    pipe_frames(&transformer, config.operation, role)
}

/// Reads the transform's `{ operation, keyId, passphrase }` options.
fn read_config(options: &JsValue) -> Result<TransformConfig, JsValue> {
    Ok(TransformConfig {
        operation: string_field(options, "operation")?,
        key_id: Reflect::get(options, &"keyId".into())?
            .as_f64()
            .ok_or("keyId missing")? as u64,
        passphrase: string_field(options, "passphrase")?,
    })
}

/// Creates the encrypt/decrypt codec keyed by the config's operation.
fn build_codec(config: &TransformConfig) -> Result<Codec, JsValue> {
    match config.operation.as_str() {
        "encrypt" => {
            let mut sender = Sender::new(config.key_id);
            sender.set_encryption_key(&config.passphrase).map_err(to_js)?;
            Ok(Codec::Encrypt(sender))
        }
        "decrypt" => {
            let mut receiver = Receiver::default();
            receiver
                .set_encryption_key(config.key_id, &config.passphrase)
                .map_err(to_js)?;
            Ok(Codec::Decrypt(receiver))
        }
        other => Err(JsValue::from_str(&format!("unknown operation {other}"))),
    }
}

/// Pipes the transform's frames through the registered codec for `operation`.
fn pipe_frames(
    transformer: &web_sys::RtcRtpScriptTransformer,
    operation: String,
    role: &'static str,
) -> Result<(), JsValue> {
    let mut frame_no = 0u32;
    let transform = Closure::<dyn FnMut(JsValue, JsValue)>::new(
        move |chunk: JsValue, controller: JsValue| {
            frame_no += 1;
            transform_frame(
                &operation,
                role,
                frame_no,
                &chunk.unchecked_into(),
                &controller.unchecked_into(),
            );
        },
    );

    let transformer_obj = Object::new();
    Reflect::set(&transformer_obj, &"transform".into(), transform.as_ref())?;
    transform.forget();

    let stream = TransformStream::new_with_transformer(&transformer_obj)?;
    let pair = ReadableWritablePair::new(&stream.readable(), &stream.writable());
    let _ = transformer
        .readable()
        .pipe_through(&pair)
        .pipe_to(&transformer.writable());
    Ok(())
}

/// Runs one frame through its codec and enqueues the result (or logs a drop).
fn transform_frame(
    operation: &str,
    role: &str,
    frame_no: u32,
    frame: &RtcEncodedVideoFrame,
    controller: &TransformStreamDefaultController,
) {
    let data = frame_bytes(frame);
    let outcome = CODECS.with(|codecs| {
        codecs
            .borrow_mut()
            .get_mut(operation)
            .map(|entry| entry.codec.process(&data))
    });
    match outcome {
        Some(Ok(out)) => {
            log_frame(role, frame_no, &data, &out);
            set_frame_bytes(frame, &out);
            let _ = controller.enqueue_with_chunk(frame.as_ref());
        }
        // Wrong key or a tampered frame: the frame is dropped, so the
        // remote video stays blank. Log why so it can be debugged.
        Some(Err(err)) => {
            log::warn!("[{role}] frame #{frame_no} dropped ({} bytes): {err}", data.len())
        }
        // Codec removed (session stopped): nothing to do.
        None => {}
    }
}

/// Logs the first few frames so the encrypt/decrypt sizes can be eyeballed.
fn log_frame(role: &str, frame_no: u32, data: &[u8], out: &[u8]) {
    if frame_no <= 3 {
        log::debug!(
            "[{role}] frame #{frame_no}: {} -> {} bytes, first byte 0x{:02x}",
            data.len(),
            out.len(),
            data.first().copied().unwrap_or(0),
        );
    }
}

/// Reads an encoded frame's payload into an owned buffer.
fn frame_bytes(frame: &RtcEncodedVideoFrame) -> Vec<u8> {
    Uint8Array::new(&frame.data()).to_vec()
}

/// Writes a payload back onto an encoded frame.
fn set_frame_bytes(frame: &RtcEncodedVideoFrame, bytes: &[u8]) {
    frame.set_data(&Uint8Array::from(bytes).buffer());
}

fn string_field(object: &JsValue, key: &str) -> Result<String, JsValue> {
    Reflect::get(object, &key.into())?
        .as_string()
        .ok_or_else(|| JsValue::from_str(&format!("{key} missing")))
}

fn to_js(err: sframe::error::SframeError) -> JsValue {
    JsValue::from_str(&err.to_string())
}
