use crate::*;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use lazy_static::lazy_static;
use libbpf_rs::{query::MapInfoIter, MapHandle, MapType};
use ratatui::{prelude::*, widgets::*};
use regex::Regex;

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
                            let (_, id) = app.maps[selected_map];
                            app.get(id)?;
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
        "cilium_(policy_\
                |tunnel_m\
                |ct4_glob\
                |metrics\
                |ct_any4_\
                |lb4_reve\
                |lb4_serv\
                |lb4_back\
                |snat_v4_\
                |lxc\
                |ipcache)"
    )
    .unwrap();
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    let name_len = app
        .maps
        .iter()
        .map(|(name, _)| name.len() - 7)
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
        .map(|map| ListItem::new(&map.0[7..]))
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
    maps: Vec<(String, u32)>,
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

    pub fn get(&mut self, id: u32) -> Result<()> {
        let map = MapHandle::from_map_id(id)?;
        let (rows, header) = match map.name() {
            "cilium_policy_0" => dump::<PolicyKey, PolicyEntry>(&map, false)?,
            "cilium_ipcache" => dump::<IpcacheKey, RemoteEndpointInfo>(&map, false)?,
            "cilium_metrics" => dump::<MetricsKey, MetricsValue>(&map, true)?,
            "cilium_tunnel_m" => dump::<TunnelKey, TunnelValue>(&map, false)?,
            "cilium_ct4_glob" | "cilium_ct_any4_" => dump::<Ipv4CtTuple, CtEntry>(&map, false)?,
            "cilium_lb4_reve" => {
                if map.map_type() == MapType::Hash {
                    dump::<Lb4ReverseNatKey, Lb4ReverseNat>(&map, false)?
                } else {
                    dump::<Ipv4RevnatTuple, Ipv4RevnatEntry>(&map, false)?
                }
            }
            "cilium_lb4_serv" => dump::<Lb4Key, Lb4Service>(&map, false)?,
            "cilium_snat_v4_" => dump::<Ipv4CtTuple, Ipv4NatEntry>(&map, false)?,
            "cilium_lb4_back" => dump::<Lb4BackendKey, Lb4Backend>(&map, false)?,
            "cilium_lxc" => dump::<EndpointKey, EndpointInfo>(&map, false)?,
            _ => {
                self.rows.clear();
                self.header.clear();
                self.name = "Not supported".to_string();
                return Ok(());
            }
        };
        self.rows = rows;
        self.header = header;
        self.name = map.name().to_string();
        Ok(())
    }

    pub fn list(&mut self) -> Result<()> {
        let map_info_iter = MapInfoIter::default();
        self.maps = map_info_iter
            .filter(|info| MAP_FILTER.is_match(&info.name))
            .map(|info| (info.name, info.id))
            .collect();
        Ok(())
    }
}
