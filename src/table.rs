use crate::*;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use itertools::Itertools;
use lazy_static::lazy_static;
use libbpf_rs::MapHandle;
use ratatui::{prelude::*, widgets::*};
use regex::Regex;
use std::path::PathBuf;
use sysinfo::{ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};

pub fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> Result<()> {
    app.list()?;
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), KeyModifiers::NONE) => return Ok(()),
                    (KeyCode::Char('j'), KeyModifiers::NONE) => app.next_map(),
                    (KeyCode::Char('k'), KeyModifiers::NONE) => app.previous_map(),
                    (KeyCode::Char('j'), KeyModifiers::CONTROL) => app.next_row(),
                    (KeyCode::Char('k'), KeyModifiers::CONTROL) => app.previous_row(),
                    (KeyCode::Char('l'), KeyModifiers::NONE) => {
                        if let Some(selected_map) = app.list_state.selected() {
                            // let (_, path) = &app.maps[selected_map];
                            app.get(selected_map)?;
                            app.content_state.select(None);
                        }
                    }
                    (KeyCode::Char('h'), KeyModifiers::NONE) => app.list()?,
                    _ => {}
                }
            }
        }
    }
}

lazy_static! {
    static ref MAP_FILTER: Regex = Regex::new(
        "^(policy\
         |tunnel map\
         |ct4 global\
         |metrics\
         |ct any4 global\
         |lb4 reverse nat\
         |lb4 reverse sk\
         |lb4 services v2\
         |lb4 backends v3\
         |snat v4 external\
         |lxc\
         |ipcache)"
    )
    .unwrap();
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    let name_len = app
        .maps
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0);
    let rects = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length((name_len + 2) as _),
                Constraint::Percentage(100),
            ]
            .as_ref(),
        )
        .margin(0)
        .split(f.size());

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let header = Row::new(app.header.clone())
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);
    let rows = app.rows.iter().map(|item| Row::new(item.clone()));
    let widths: Vec<_> = (0..app.header.len())
        .map(|i| {
            let width = app.header[i].len();
            app.rows
                .iter()
                .map(|row| row[i].len())
                .max()
                .unwrap_or(0)
                .max(width) as _
        })
        .map(Constraint::Length)
        .collect();
    let t = Table::new(rows)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            "{} {}/{}",
            app.name.clone(),
            app.content_state.selected().map(|i| i + 1).unwrap_or(0),
            app.rows.len()
        )))
        .widths(&widths)
        .column_spacing(2)
        .highlight_style(selected_style);
    f.render_stateful_widget(t, rects[1], &mut app.content_state);

    let map_names: Vec<_> = app
        .maps
        .iter()
        .map(|map| ListItem::new(&map.0[..]))
        .collect();
    let maps = List::new(map_names)
        .block(
            Block::default()
                .borders(Borders::BOTTOM | Borders::LEFT | Borders::TOP)
                .title("maps"),
        )
        .highlight_style(selected_style);
    f.render_stateful_widget(maps, rects[0], &mut app.list_state);
}

#[derive(Default)]
pub struct App {
    content_state: TableState,
    list_state: ListState,
    rows: Vec<Vec<String>>,
    header: Vec<&'static str>,
    name: String,
    maps: Vec<(String, PathBuf)>,
}

impl App {
    pub fn next_row(&mut self) {
        let i = match self.content_state.selected() {
            Some(i) => {
                if i >= self.rows.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.content_state.select(Some(i));
    }

    pub fn previous_row(&mut self) {
        let i = match self.content_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.rows.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.content_state.select(Some(i));
    }

    pub fn next_map(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.maps.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn previous_map(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.maps.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    pub fn get(&mut self, selected_map: usize) -> Result<()> {
        // let map = MapHandle::from_map_id(id)?;
        let (name, path) = &self.maps[selected_map];
        let map = MapHandle::from_pinned_path(path)?;
        let (rows, header) = match name.as_str() {
            "ipcache" => dump::<IpcacheKey, RemoteEndpointInfo>(&map, false)?,
            "metrics" => dump::<MetricsKey, MetricsValue>(&map, true)?,
            "tunnel map" => dump::<TunnelKey, TunnelValue>(&map, false)?,
            "ct4 global" | "ct any4 global" => dump::<Ipv4CtTuple, CtEntry>(&map, false)?,
            "lb4 reverse nat" => dump::<Lb4ReverseNatKey, Lb4ReverseNat>(&map, false)?,
            "lb4 reverse sk" => dump::<Ipv4RevnatTuple, Ipv4RevnatEntry>(&map, false)?,
            "lb4 services v2" => dump::<Lb4Key, Lb4Service>(&map, false)?,
            "snat v4 external" => dump::<Ipv4CtTuple, Ipv4NatEntry>(&map, false)?,
            "lb4 backends v3" => dump::<Lb4BackendKey, Lb4Backend>(&map, false)?,
            "lxc" => dump::<EndpointKey, EndpointInfo>(&map, false)?,
            _ => {
                if name.starts_with("policy") {
                    dump::<PolicyKey, PolicyEntry>(&map, false)?
                } else {
                    self.rows.clear();
                    self.header.clear();
                    self.name = "Not supported".to_string();
                    return Ok(());
                }
            }
        };
        self.rows = rows;
        self.header = header;
        self.name = name.to_owned();
        Ok(())
    }

    pub fn list(&mut self) -> Result<()> {
        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new()),
        );
        let cilium_agent = system.processes_by_name("cilium-agent");
        self.maps = cilium_agent
            .flat_map(|process| {
                let bpf_path = format!("/proc/{}/root/sys/fs/bpf/tc/globals", process.pid());
                std::fs::read_dir(bpf_path)
                    .unwrap()
                    .map(|entry| {
                        let dir = entry.unwrap();
                        (
                            dir.file_name().to_string_lossy().to_string()[7..].replace('_', " "),
                            dir.path(),
                        )
                    })
                    .filter(|(name, _)| MAP_FILTER.is_match(name))
            })
            .sorted()
            .collect();
        Ok(())
    }
}
