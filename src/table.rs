use ratatui::{prelude::*, widgets::*};

pub fn table(rows: Vec<Vec<String>>, header: Vec<&'static str>, title: String) -> Table {
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    Table::new(rows.into_iter().map(|r| Row::new(r)).collect::<Vec<_>>())
        .header(Row::new(header))
        .highlight_style(selected_style)
        .block(Block::default().borders(Borders::ALL).title(title))
}
