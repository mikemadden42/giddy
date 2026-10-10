//! Rendering.

use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Table, Wrap,
};

use crate::app::{App, Mode};
use crate::device::{Device, Sources, describe_service, looks_opaque};

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn muted() -> Style {
    Style::new().fg(MUTED)
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)]).areas(f.area());

    draw_header(f, app, header);
    draw_footer(f, app, footer);

    if app.details {
        let lines = detail_lines(app);
        let (list, details) = if body.width >= 130 {
            let [l, d] = Layout::horizontal([Constraint::Min(60), Constraint::Length(52)]).areas(body);
            (l, d)
        } else {
            let height = (lines.len() as u16 + 2).min(body.height / 2).max(5);
            let [l, d] = Layout::vertical([Constraint::Min(6), Constraint::Length(height)]).areas(body);
            (l, d)
        };
        draw_table(f, app, list);
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(ACCENT))
            .title(Span::styled(" Details ", Style::new().bold()));
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), details);
    } else {
        draw_table(f, app, body);
    }

    match &app.mode {
        Mode::Help => draw_help(f),
        Mode::Interfaces(cursor) => draw_interfaces(f, app, *cursor),
        Mode::Alias(input) => draw_alias(f, app, input),
        _ => {}
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let iface = app.current_iface();
    let left = Line::from(vec![
        Span::styled(" giddy ", Style::new().bg(ACCENT).fg(Color::Black).bold()),
        Span::styled(concat!(" v", env!("CARGO_PKG_VERSION"), "  "), muted()),
        Span::styled(iface.name.as_str(), Style::new().fg(ACCENT).bold()),
        Span::raw(" "),
        Span::raw(iface.cidr()),
    ]);

    let st = &app.status;
    let mut right: Vec<Span> = Vec::new();
    if st.busy() {
        right.push(Span::styled(SPINNER[app.frame % SPINNER.len()], Style::new().fg(ACCENT)));
        right.push(Span::raw(" "));
        let mut tasks = Vec::new();
        if st.sweeping {
            let (done, total) = st.sweep.unwrap_or((0, 0));
            tasks.push(format!("sweep {done}/{total}"));
        }
        if st.mdns {
            tasks.push("mDNS".into());
        }
        if st.ssdp {
            tasks.push("SSDP".into());
        }
        if st.netbios {
            tasks.push("NetBIOS".into());
        }
        right.push(Span::raw(tasks.join(" · ")));
    } else if let Some(next) = st.next_at {
        let secs = next.saturating_duration_since(Instant::now()).as_secs();
        right.push(Span::styled(format!("● idle · next scan in {secs}s"), muted()));
    }
    right.push(Span::raw("  "));
    let count = app.devices.len();
    right.push(Span::styled(format!("{count} device{} ", if count == 1 { "" } else { "s" }), Style::new().bold()));
    let right = Line::from(right).alignment(Alignment::Right);

    f.render_widget(left, area);
    f.render_widget(right, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints: &[(&str, &str)] = match app.mode {
        Mode::Filter => &[("type", "filter"), ("enter", "done"), ("esc", "clear")],
        Mode::Alias(_) => &[("enter", "save (empty clears)"), ("esc", "cancel")],
        Mode::Interfaces(_) => &[("↑↓", "choose"), ("enter", "scan"), ("esc", "cancel")],
        Mode::Help => &[("any key", "close")],
        Mode::Normal => &[
            ("↑↓/jk", "move"),
            ("enter", "details"),
            ("/", "filter"),
            ("s", "sort"),
            ("a", "alias"),
            ("y/Y", "copy IP/MAC"),
            ("i", "interface"),
            ("r", "rescan"),
            ("?", "help"),
            ("q", "quit"),
        ],
    };
    let mut spans = vec![Span::raw(" ")];
    for (i, (key, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", muted()));
        }
        spans.push(Span::styled(*key, Style::new().fg(ACCENT).bold()));
        spans.push(Span::styled(format!(" {label}"), muted()));
    }
    f.render_widget(Line::from(spans), area);

    if let Some((msg, _)) = &app.toast {
        let width = (msg.chars().count() as u16 + 2).min(area.width);
        let toast_area = Rect { x: area.right() - width, width, ..area };
        f.render_widget(Clear, toast_area);
        f.render_widget(
            Line::from(Span::styled(format!(" {msg} "), Style::new().bg(Color::Yellow).fg(Color::Black))),
            toast_area,
        );
    }
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    let total = app.devices.len();
    let mut title = vec![Span::styled(" Devices ", Style::new().bold())];
    if app.filter.is_empty() {
        title.push(Span::styled(format!("({total}) "), Style::new().fg(ACCENT)));
    } else {
        title.push(Span::styled(format!("({}/{total}) ", app.view.len()), Style::new().fg(ACCENT)));
    }
    if matches!(app.mode, Mode::Filter) || !app.filter.is_empty() {
        let cursor = if matches!(app.mode, Mode::Filter) { "▏" } else { "" };
        title.push(Span::styled("/", Style::new().fg(Color::Yellow).bold()));
        title.push(Span::styled(format!("{}{cursor} ", app.filter), Style::new().fg(Color::Yellow)));
    }
    let arrow = if app.sort_desc { "↓" } else { "↑" };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(muted())
        .title(Line::from(title))
        .title_top(Line::styled(format!(" sort: {} {arrow} ", app.sort.label()), muted()).right_aligned());

    let wide = area.width >= 110;
    let show_vendor = area.width >= 80;
    let mut header = vec!["IP", "Name", "MAC"];
    let mut widths = vec![Constraint::Length(15), Constraint::Fill(3), Constraint::Length(17)];
    if show_vendor {
        header.push("Manufacturer");
        widths.push(Constraint::Fill(2));
    }
    if wide {
        header.push("Via");
        widths.push(Constraint::Length(5));
    }
    header.push("Seen");
    widths.push(Constraint::Length(5));

    let stale_after = (app.cfg.interval * 3).max(Duration::from_secs(90));
    let rows = app.view.iter().filter_map(|ip| app.devices.get(ip)).map(|d| {
        let stale = d.last_seen.elapsed() > stale_after;
        let mut cells = vec![
            Cell::from(d.ip.to_string()),
            Cell::from(name_line(d)),
            Cell::from(d.mac.map(|m| m.to_string()).unwrap_or_default()),
        ];
        if show_vendor {
            cells.push(Cell::from(vendor_span(d)));
        }
        if wide {
            cells.push(Cell::from(sources_line(d)));
        }
        cells.push(Cell::from(Line::from(ago(d.last_seen.elapsed())).right_aligned()));
        let row = Row::new(cells);
        if stale { row.style(muted()) } else { row }
    });

    let table = Table::new(rows, widths)
        .header(Row::new(header).style(Style::new().fg(ACCENT).bold()).bottom_margin(0))
        .block(block)
        .column_spacing(2)
        .row_highlight_style(Style::new().bg(Color::Indexed(237)).add_modifier(Modifier::BOLD))
        .highlight_symbol(Span::styled("▌", Style::new().fg(ACCENT)));

    if app.view.is_empty() {
        f.render_widget(table, area);
        let msg = if !app.filter.is_empty() {
            "No devices match the filter".to_string()
        } else if app.status.busy() || app.status.cycles == 0 {
            format!("{} Discovering devices…", SPINNER[app.frame % SPINNER.len()])
        } else {
            "No devices found".to_string()
        };
        let inner = area.inner(Margin::new(1, 2));
        f.render_widget(Paragraph::new(msg).style(muted()).alignment(Alignment::Center), inner);
        return;
    }

    f.render_stateful_widget(table, area, &mut app.table);

    let visible = area.height.saturating_sub(3) as usize;
    if app.view.len() > visible {
        let mut sb = ScrollbarState::new(app.view.len().saturating_sub(visible)).position(app.table.offset());
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight).begin_symbol(None).end_symbol(None),
            area.inner(Margin::new(0, 1)),
            &mut sb,
        );
    }
}

fn name_line(d: &Device) -> Line<'_> {
    let mut spans = Vec::new();
    match d.display_name() {
        Some(name) if d.alias.is_some() => spans.push(Span::styled(name, Style::new().fg(Color::Yellow))),
        Some(name) => spans.push(Span::raw(name)),
        None => spans.push(Span::styled("—", muted())),
    }
    if d.is_gateway && !d.display_name().is_some_and(|n| n.to_lowercase().contains("gateway")) {
        spans.push(Span::styled(" gateway", Style::new().fg(Color::Magenta)));
    }
    if d.is_self {
        spans.push(Span::styled(" (this device)", Style::new().fg(Color::Green)));
    }
    Line::from(spans)
}

fn vendor_span(d: &Device) -> Span<'_> {
    match (d.manufacturer(), d.mac) {
        (Some(v), _) => Span::raw(v),
        (None, Some(m)) if m.is_local() => Span::styled("private address", muted().italic()),
        _ => Span::raw(""),
    }
}

/// Compact badges for the discovery mechanisms that saw a device.
fn sources_line(d: &Device) -> Line<'static> {
    let badge = |src: Sources, ch: &'static str, color: Color| {
        if d.sources.contains(src) { Span::styled(ch, Style::new().fg(color)) } else { Span::styled("·", muted()) }
    };
    Line::from(vec![
        badge(Sources::ARP, "A", Color::Blue),
        badge(Sources::MDNS, "M", Color::Green),
        badge(Sources::SSDP, "U", Color::Magenta),
        badge(Sources::TCP, "T", Color::Yellow),
        badge(Sources::NETBIOS, "N", Color::Red),
    ])
}

fn ago(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        _ => format!("{}h", s / 3600),
    }
}

fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let Some(d) = app.selected_device() else {
        return vec![Line::styled("No device selected", muted())];
    };

    let key = |k: &str| Span::styled(format!("{k:<13}"), muted());
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(d.display_name().unwrap_or("Unnamed device").to_string(), Style::new().bold())),
        Line::raw(""),
    ];
    let mut field = |k: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            lines.push(Line::from(vec![key(k), Span::raw(v)]));
        }
    };
    field("IP", Some(d.ip.to_string()));
    field("MAC", d.mac.map(|m| if m.is_local() { format!("{m} (randomized)") } else { m.to_string() }));
    field("Manufacturer", d.manufacturer().map(String::from));
    field("Model", d.model().map(String::from));
    field("mDNS host", d.mdns_host.as_ref().map(|h| format!("{h}.local")));
    field("NetBIOS name", d.netbios_name.clone());
    field("Workgroup", d.workgroup.clone());
    field("DNS name", d.rdns.clone());
    if let Some(ssdp) = &d.ssdp {
        field("UPnP name", ssdp.friendly_name.clone());
        field("UPnP server", ssdp.server.clone());
    }
    if !d.open_ports.is_empty() {
        let ports: Vec<String> = d.open_ports.iter().map(u16::to_string).collect();
        field("Open ports", Some(ports.join(", ")));
    }
    let mut via = Vec::new();
    for (src, name) in [
        (Sources::ARP, "ARP"),
        (Sources::MDNS, "mDNS"),
        (Sources::SSDP, "SSDP"),
        (Sources::TCP, "TCP"),
        (Sources::NETBIOS, "NetBIOS"),
    ] {
        if d.sources.contains(src) {
            via.push(name);
        }
    }
    field("Seen via", Some(via.join(", ")));
    field("First seen", Some(format!("{} ago", ago(d.first_seen.elapsed()))));
    field("Last seen", Some(format!("{} ago", ago(d.last_seen.elapsed()))));

    if !d.services.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Services", Style::new().fg(ACCENT).bold()));
        for (svc, instance) in &d.services {
            let mut spans = vec![Span::raw(format!("{:<18}", describe_service(svc)))];
            if !looks_opaque(instance) {
                spans.push(Span::styled(instance.clone(), muted()));
            }
            lines.push(Line::from(spans));
        }
    }

    lines
}

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(height.min(area.height))]).flex(Flex::Center).areas(area);
    let [h] = Layout::horizontal([Constraint::Length(width.min(area.width))]).flex(Flex::Center).areas(v);
    h
}

fn popup_block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(format!(" {title} "), Style::new().bold()))
}

fn draw_interfaces(f: &mut Frame, app: &App, cursor: usize) {
    let height = app.ifaces.len() as u16 + 2;
    let area = popup(f.area(), 56, height);
    let items: Vec<ListItem> = app
        .ifaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let mark = if i == app.iface { "● " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(mark, Style::new().fg(ACCENT)),
                Span::styled(format!("{:<18}", iface.name), Style::new().bold()),
                Span::raw(iface.cidr()),
            ]))
        })
        .collect();
    let list =
        List::new(items).block(popup_block("Interface")).highlight_style(Style::new().bg(Color::Indexed(237)).bold());
    let mut state = ListState::default().with_selected(Some(cursor));
    f.render_widget(Clear, area);
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_alias(f: &mut Frame, app: &App, input: &str) {
    let area = popup(f.area(), 50, 5);
    let target = app.selected_device().map(|d| d.ip.to_string()).unwrap_or_default();
    let text = Text::from(vec![
        Line::styled(format!("Name for {target}:"), muted()),
        Line::from(vec![Span::raw(input), Span::styled("▏", Style::new().fg(ACCENT))]),
    ]);
    f.render_widget(Clear, area);
    f.render_widget(Paragraph::new(text).block(popup_block("Alias")), area);
}

fn draw_help(f: &mut Frame) {
    let keys: &[(&str, &str)] = &[
        ("↑ ↓  j k", "Move selection"),
        ("PgUp PgDn", "Page up / down"),
        ("g G", "First / last device"),
        ("Enter", "Toggle details panel"),
        ("/", "Filter by IP, name, MAC, vendor"),
        ("s  S", "Cycle sort column / reverse"),
        ("a", "Set alias for device (by MAC)"),
        ("y  Y", "Copy IP / MAC to clipboard"),
        ("i", "Choose network interface"),
        ("r", "Rescan now"),
        ("q  Ctrl-C", "Quit"),
    ];
    let mut lines: Vec<Line> = keys
        .iter()
        .map(|(k, v)| Line::from(vec![Span::styled(format!("{k:<12}"), Style::new().fg(ACCENT).bold()), Span::raw(*v)]))
        .collect();
    lines.push(Line::raw(""));
    lines.push(Line::styled("Via column:", muted()));
    lines.push(Line::from(vec![
        Span::styled("A", Style::new().fg(Color::Blue)),
        Span::styled(" ARP  ", muted()),
        Span::styled("M", Style::new().fg(Color::Green)),
        Span::styled(" mDNS  ", muted()),
        Span::styled("U", Style::new().fg(Color::Magenta)),
        Span::styled(" UPnP/SSDP  ", muted()),
        Span::styled("T", Style::new().fg(Color::Yellow)),
        Span::styled(" TCP  ", muted()),
        Span::styled("N", Style::new().fg(Color::Red)),
        Span::styled(" NetBIOS", muted()),
    ]));
    let area = popup(f.area(), 52, lines.len() as u16 + 2);
    f.render_widget(Clear, area);
    f.render_widget(Paragraph::new(lines).block(popup_block("Keys")), area);
}
