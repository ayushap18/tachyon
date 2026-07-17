mod ai_bar;
mod app;
mod blocks;
mod bridge;
mod palette;
mod settings;
mod status;
mod terminal;
mod theme;
mod vim;

fn main() {
    dioxus::launch(app::App);
}
