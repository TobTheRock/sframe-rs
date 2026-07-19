//! Sets up the loopback call and attaches the sframe Encoded Transforms.
//!
//! Everything runs in one page: `pc1` sends the camera track to `pc2`. The
//! sender's frames are encrypted in the worker, the receiver's are decrypted.

use js_sys::{Array, Object, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    HtmlVideoElement, MediaStream, MediaStreamConstraints, MediaStreamTrack, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcRtpScriptTransform, RtcRtpTransceiverDirection,
    RtcRtpTransceiverInit, RtcSessionDescriptionInit, RtcTrackEvent, Worker,
};

use crate::KEY_ID;

/// A running loopback call. Keep it alive for the call to continue; drop or
/// [`stop`](Session::stop) it to tear the call down.
#[derive(Clone)]
pub struct Session {
    pc1: RtcPeerConnection,
    pc2: RtcPeerConnection,
    worker: Worker,
    stream: MediaStream,
}

impl Session {
    /// Closes the peer connections, stops the camera, and terminates the worker.
    pub fn stop(&self) {
        self.pc1.close();
        self.pc2.close();
        self.worker.terminate();
        self.stream
            .get_tracks()
            .iter()
            .for_each(|track| track.unchecked_into::<MediaStreamTrack>().stop());
    }

    /// Re-derives both sides' keys from new passphrases, live. Making them differ
    /// breaks decryption without restarting the call.
    pub fn rekey(&self, send_pass: &str, recv_pass: &str) -> Result<(), JsValue> {
        let message = Object::new();
        Reflect::set(&message, &"sendPass".into(), &send_pass.into())?;
        Reflect::set(&message, &"recvPass".into(), &recv_pass.into())?;
        self.worker.post_message(&message)
    }
}

/// Starts a fresh loopback call. `send_pass`/`recv_pass` are the two passphrases;
/// mismatch them to watch decryption fail.
pub async fn start(
    send_pass: String,
    recv_pass: String,
    local: HtmlVideoElement,
    remote: HtmlVideoElement,
) -> Result<Session, JsValue> {
    let worker = Worker::new("./worker-bootstrap.js")?;
    let stream = open_camera(&local).await?;

    let pc1 = RtcPeerConnection::new()?;
    let pc2 = RtcPeerConnection::new()?;
    trickle_ice(&pc1, &pc2);
    trickle_ice(&pc2, &pc1);

    attach_receiver(&pc2, &worker, recv_pass, remote);
    attach_sender(&pc1, &stream, &worker, &send_pass)?;

    negotiate(&pc1, &pc2).await?;
    Ok(Session {
        pc1,
        pc2,
        worker,
        stream,
    })
}

/// Opens the camera and shows the raw feed in the `local` video element.
async fn open_camera(local: &HtmlVideoElement) -> Result<MediaStream, JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let media = window.navigator().media_devices()?;
    let constraints = MediaStreamConstraints::new();
    constraints.set_video(&JsValue::TRUE);
    let stream: MediaStream =
        JsFuture::from(media.get_user_media_with_constraints(&constraints)?)
            .await?
            .unchecked_into();
    local.set_src_object(Some(&stream));
    Ok(stream)
}

/// Decrypts each incoming frame on `pc2` and shows the result in `remote`.
fn attach_receiver(
    pc2: &RtcPeerConnection,
    worker: &Worker,
    recv_pass: String,
    remote: HtmlVideoElement,
) {
    let worker = worker.clone();
    let on_track = Closure::<dyn FnMut(RtcTrackEvent)>::new(move |event: RtcTrackEvent| {
        let transform = RtcRtpScriptTransform::new_with_options(
            &worker,
            &transform_options("decrypt", &recv_pass),
        )
        .expect("script transform");
        event
            .receiver()
            .set_transform_opt_rtc_rtp_script_transform(Some(&transform));

        // `add_transceiver` carries no msid, so `event.streams()` is empty.
        // Wrap the track in a fresh stream to feed the video element.
        let stream = MediaStream::new().expect("media stream");
        stream.add_track(&event.track());
        remote.set_src_object(Some(&stream));
    });
    pc2.set_ontrack(Some(on_track.as_ref().unchecked_ref()));
    on_track.forget();
}

/// Forces VP8 on `pc1`'s video track and encrypts each outgoing frame.
fn attach_sender(
    pc1: &RtcPeerConnection,
    stream: &MediaStream,
    worker: &Worker,
    send_pass: &str,
) -> Result<(), JsValue> {
    let track: MediaStreamTrack = stream.get_video_tracks().get(0).unchecked_into();
    let init = RtcRtpTransceiverInit::new();
    init.set_direction(RtcRtpTransceiverDirection::Sendonly);
    let transceiver = pc1.add_transceiver_with_media_stream_track_and_init(&track, &init);
    prefer_vp8(&transceiver)?;

    let transform =
        RtcRtpScriptTransform::new_with_options(worker, &transform_options("encrypt", send_pass))?;
    transceiver
        .sender()
        .set_transform_opt_rtc_rtp_script_transform(Some(&transform));
    Ok(())
}

/// Forwards ICE candidates from `from` to `to`, completing the loopback.
fn trickle_ice(from: &RtcPeerConnection, to: &RtcPeerConnection) {
    let to = to.clone();
    let on_ice = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(move |event: RtcPeerConnectionIceEvent| {
        if let Some(candidate) = event.candidate() {
            let _ = to.add_ice_candidate_with_opt_rtc_ice_candidate(Some(&candidate));
        }
    });
    from.set_onicecandidate(Some(on_ice.as_ref().unchecked_ref()));
    on_ice.forget();
}

/// Restricts the transceiver to VP8 so the worker can rely on the VP8 header
/// layout (see [`crate::transform`]).
fn prefer_vp8(transceiver: &web_sys::RtcRtpTransceiver) -> Result<(), JsValue> {
    let caps = web_sys::RtcRtpSender::get_capabilities("video").ok_or("no video caps")?;
    let codecs: Array = Reflect::get(&caps, &"codecs".into())?.unchecked_into();
    let vp8: Array = codecs
        .iter()
        .filter(|codec| {
            Reflect::get(codec, &"mimeType".into())
                .ok()
                .and_then(|m| m.as_string())
                .is_some_and(|m| m.eq_ignore_ascii_case("video/VP8"))
        })
        .collect();
    transceiver.set_codec_preferences(&vp8);
    Ok(())
}

/// The options object handed to the worker for one transform.
fn transform_options(operation: &str, passphrase: &str) -> Object {
    let options = Object::new();
    let _ = Reflect::set(&options, &"operation".into(), &operation.into());
    let _ = Reflect::set(&options, &"keyId".into(), &JsValue::from_f64(KEY_ID as f64));
    let _ = Reflect::set(&options, &"passphrase".into(), &passphrase.into());
    options
}

/// Standard offer/answer exchange between the two local peer connections.
async fn negotiate(pc1: &RtcPeerConnection, pc2: &RtcPeerConnection) -> Result<(), JsValue> {
    let offer: RtcSessionDescriptionInit = JsFuture::from(pc1.create_offer()).await?.unchecked_into();
    JsFuture::from(pc1.set_local_description(&offer)).await?;
    JsFuture::from(pc2.set_remote_description(&offer)).await?;

    let answer: RtcSessionDescriptionInit =
        JsFuture::from(pc2.create_answer()).await?.unchecked_into();
    JsFuture::from(pc2.set_local_description(&answer)).await?;
    JsFuture::from(pc1.set_remote_description(&answer)).await?;
    Ok(())
}
