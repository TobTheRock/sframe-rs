//! Leptos UI for the demo: two videos, two passphrases, start/stop and a live
//! "update passphrases" button.

use std::cell::RefCell;
use std::rc::Rc;

use leptos::html;
use leptos::prelude::*;
use sframe_wasm_webrtc::webrtc::{self, Session};
use wasm_bindgen_futures::spawn_local;

/// The current text of an input, if it is mounted.
fn value_of(input: NodeRef<html::Input>) -> Option<String> {
    input.get_untracked().map(|input| input.value())
}

/// Detaches whatever stream a video element is showing.
fn clear_video(video: NodeRef<html::Video>) {
    if let Some(video) = video.get_untracked() {
        video.set_src_object(None);
    }
}

#[component]
fn App() -> impl IntoView {
    let local_ref = NodeRef::<leptos::html::Video>::new();
    let remote_ref = NodeRef::<leptos::html::Video>::new();
    let send_ref = NodeRef::<leptos::html::Input>::new();
    let recv_ref = NodeRef::<leptos::html::Input>::new();

    let status = RwSignal::new(String::new());
    let running = RwSignal::new(false);
    // The live call, if any. Kept out of a signal because web-sys handles are
    // !Send; only `running` needs to be reactive.
    let session: Rc<RefCell<Option<Session>>> = Rc::new(RefCell::new(None));

    let stop_call = {
        let session = session.clone();
        move || {
            if let Some(call) = session.borrow_mut().take() {
                call.stop();
            }
            clear_video(local_ref);
            clear_video(remote_ref);
            running.set(false);
        }
    };

    let start_call = {
        let session = session.clone();
        move || {
            let (Some(local), Some(remote)) =
                (local_ref.get_untracked(), remote_ref.get_untracked())
            else {
                return;
            };
            let (Some(send_pass), Some(recv_pass)) = (value_of(send_ref), value_of(recv_ref))
            else {
                return;
            };
            status.set(String::new());
            running.set(true);

            let session = session.clone();
            spawn_local(async move {
                match webrtc::start(send_pass, recv_pass, local, remote).await {
                    Ok(call) => *session.borrow_mut() = Some(call),
                    Err(err) => {
                        status.set(format!("{err:?}"));
                        running.set(false);
                    }
                }
            });
        }
    };

    let toggle = move |_| {
        if running.get_untracked() {
            stop_call();
        } else {
            start_call();
        }
    };

    let update = {
        let session = session.clone();
        move |_| {
            let (Some(send_pass), Some(recv_pass)) = (value_of(send_ref), value_of(recv_ref))
            else {
                return;
            };
            if let Some(call) = session.borrow().as_ref() {
                if let Err(err) = call.rekey(&send_pass, &recv_pass) {
                    status.set(format!("{err:?}"));
                }
            }
        }
    };

    view! {
        <h1>"sframe WebRTC demo"</h1>
        <p>
            "One page, two peer connections in loopback. The sender encrypts every VP8 "
            "frame with sframe; the receiver decrypts it. Give the two sides different "
            "passphrases (then Update, or Start) and the remote video stays blank."
        </p>

        <div class="row">
            <label>"Sender passphrase" <input node_ref=send_ref value="correct horse battery staple"/></label>
            <label>"Receiver passphrase" <input node_ref=recv_ref value="correct horse battery staple"/></label>
        </div>

        <p>
            <button on:click=toggle>{move || if running.get() { "Stop" } else { "Start" }}</button>
            " "
            <button on:click=update disabled=move || !running.get()>"Update passphrases"</button>
            " "
            <span class="status">{move || status.get()}</span>
        </p>

        <div class="row">
            <div><h3>"Local"</h3><video node_ref=local_ref autoplay=true muted=true playsinline=true></video></div>
            <div><h3>"Remote (decrypted)"</h3><video node_ref=remote_ref autoplay=true playsinline=true></video></div>
        </div>
    }
}

fn main() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).ok();
    leptos::mount::mount_to_body(App);
}
