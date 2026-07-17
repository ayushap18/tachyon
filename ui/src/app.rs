use dioxus::prelude::*;

use crate::terminal::Terminal;

const MAIN_CSS: Asset = asset!("/assets/main.css");

#[component]
pub fn App() -> Element {
    rsx! {
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        Terminal {}
    }
}
