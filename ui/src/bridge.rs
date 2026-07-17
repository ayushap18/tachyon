//! Tauri <-> WASM bridge. The Dioxus app runs inside the Tauri webview with
//! `app.withGlobalTauri = true`, so `window.__TAURI__` is present.

use serde::Serialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    // window.__TAURI__.core.invoke(cmd, args) -> Promise
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke, catch)]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    // window.__TAURI__.event.listen(event, handler) -> Promise<UnlistenFn>
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"], js_name = listen)]
    fn tauri_listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>) -> js_sys::Promise;
}

/// Invoke a Tauri command. `args` is serialized to a JS object (its fields
/// become the command's named parameters).
pub async fn invoke<T: Serialize>(cmd: &str, args: T) -> Result<JsValue, JsValue> {
    let args = serde_wasm_bindgen::to_value(&args).map_err(JsValue::from)?;
    tauri_invoke(cmd, args).await
}

/// Listen for a Tauri event. Tauri delivers `{ event, id, payload }`; the
/// callback receives just `payload`. The closure is leaked for the app's
/// lifetime (ponytail: single global listener per event, never torn down).
pub fn listen(event: &str, mut cb: impl FnMut(JsValue) + 'static) {
    let closure = Closure::wrap(Box::new(move |ev: JsValue| {
        let payload = js_sys::Reflect::get(&ev, &JsValue::from_str("payload"))
            .unwrap_or(JsValue::NULL);
        cb(payload);
    }) as Box<dyn FnMut(JsValue)>);
    let _ = tauri_listen(event, &closure);
    closure.forget();
}
