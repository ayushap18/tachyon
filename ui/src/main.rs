mod ai_bar;
mod app;
mod blocks;
mod bridge;
mod keymap;
mod palette;
mod scroll;
mod settings;
mod status;
mod terminal;
mod theme;
mod vim;

fn main() {
    dioxus::launch(app::App);
}
