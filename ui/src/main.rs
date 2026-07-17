mod app;
mod bridge;
mod terminal;

fn main() {
    dioxus::launch(app::App);
}
