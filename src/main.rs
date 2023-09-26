use anyhow::Result;
use cilium_map_viewer::*;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io::Stdout;

struct UI {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl UI {
    fn new() -> Result<Self> {
        let stdout = std::io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        execute!(std::io::stdout(), EnterAlternateScreen)?;
        self.terminal.hide_cursor()?;
        self.terminal.clear()?;
        let app = App::default();
        run_app(&mut self.terminal, app)
    }
}

impl Drop for UI {
    fn drop(&mut self) {
        if let Err(e) = disable_raw_mode() {
            println!("Error disabling raw mode: {}", e);
        }
        if let Err(e) = crossterm::execute!(std::io::stdout(), LeaveAlternateScreen) {
            println!("Error leaving alternate screen: {}", e);
        }
        if let Err(e) = self.terminal.show_cursor() {
            println!("Error showing cursor: {}", e);
        }
    }
}

fn main() -> Result<()> {
    let mut ui = UI::new()?;
    ui.run()
}
