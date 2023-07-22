use anyhow::Result;
use bitflags::bitflags;
use cilium_map_viewer::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use std::fmt;
use tuitable::TuiTable;
use tuitable_derive::TuiTable;

fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let app = App::default();
    let res = run_app(&mut terminal, app, 107);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    res
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App, id: u32) -> Result<()> {
    let (rows, header, name) = dump::<Ipv4RevnatTuple, Ipv4RevnatEntry>(id)?;
    app.rows = rows;
    app.header = header;
    app.name = name;
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('j') => app.next(),
                    KeyCode::Char('k') => app.previous(),
                    _ => {}
                }
            }
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    let rects = Layout::default()
        .constraints([Constraint::Percentage(100)].as_ref())
        .margin(0)
        .split(f.size());

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let header = Row::new(app.header.clone());
    let rows = app.rows.iter().map(|item| Row::new(item.clone()));
    let widths = vec![(Constraint::Percentage((100 / app.header.len()) as u16)); app.header.len()];
    let t = Table::new(rows)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.name.clone()),
        )
        .widths(&widths)
        .highlight_style(selected_style);
    f.render_stateful_widget(t, rects[0], &mut app.state);
}

#[derive(Default)]
struct App {
    state: TableState,
    rows: Vec<Vec<String>>,
    header: Vec<&'static str>,
    name: String,
}

impl App {
    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.rows.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.rows.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}
