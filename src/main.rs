#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui;
use rdp_manager::{db::Store, launch, model::Connection};
use std::collections::BTreeMap;

fn db_path() -> std::path::PathBuf {
    let dir = dirs::data_dir().unwrap_or_else(|| ".".into()).join("rdp-manager");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("connections.db")
}

#[cfg(any(windows, target_os = "macos"))]
fn auto_open() -> Option<Result<Store, String>> {
    Some(Store::open_with_keyring(&db_path()).map_err(|e| e.to_string()))
}
#[cfg(not(any(windows, target_os = "macos")))]
fn auto_open() -> Option<Result<Store, String>> {
    None
}

struct App {
    store: Option<Store>,
    password: String,
    error: String,
    items: Vec<Connection>,
    selected: Option<usize>,
    edit: Connection,
    search: String,
    status: String,
}

impl App {
    fn new() -> Self {
        let (store, error) = match auto_open() {
            Some(Ok(s)) => (Some(s), String::new()),
            Some(Err(e)) => (None, e),
            None => (None, String::new()),
        };
        let mut app = Self { store, password: String::new(), error, items: vec![], selected: None, edit: Connection::default(), search: String::new(), status: String::new() };
        app.reload();
        app
    }

    fn reload(&mut self) {
        if let Some(s) = &self.store {
            match s.list() {
                Ok(l) => self.items = l,
                Err(e) => self.status = e.to_string(),
            }
        }
    }

    fn select(&mut self, id: &str) {
        self.selected = self.items.iter().position(|c| c.id == id);
        if let Some(i) = self.selected {
            self.edit = self.items[i].clone();
        }
    }

    fn unlock_ui(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.heading("RDP Manager");
            ui.label("Voer je hoofdwachtwoord in (bij de eerste keer wordt het ingesteld).");
            let r = ui.add(egui::TextEdit::singleline(&mut self.password).password(true).hint_text("hoofdwachtwoord"));
            let go = ui.button("Ontgrendelen").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if go && !self.password.is_empty() {
                match Store::open_with_password(&db_path(), &self.password) {
                    Ok(s) => {
                        self.store = Some(s);
                        self.error.clear();
                        self.password.clear();
                        self.reload();
                    }
                    Err(e) => self.error = e.to_string(),
                }
            }
            if !self.error.is_empty() {
                ui.colored_label(egui::Color32::LIGHT_RED, &self.error);
            }
        });
    }

    fn main_ui(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("list").default_size(260.0).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Zoeken…").desired_width(170.0));
                if ui.button("➕ Nieuw").clicked() {
                    self.selected = None;
                    self.edit = Connection::default();
                }
            });
            ui.separator();
            let q = self.search.to_lowercase();
            let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (i, c) in self.items.iter().enumerate() {
                if q.is_empty() || c.name.to_lowercase().contains(&q) || c.host.to_lowercase().contains(&q) || c.folder.to_lowercase().contains(&q) {
                    groups.entry(c.folder.clone()).or_default().push(i);
                }
            }
            let mut pick: Option<(String, bool)> = None;
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (folder, idxs) in &groups {
                    let title = if folder.is_empty() { "(geen map)".to_string() } else { folder.clone() };
                    egui::CollapsingHeader::new(title).default_open(true).id_salt(folder).show(ui, |ui| {
                        for &i in idxs {
                            let c = &self.items[i];
                            let r = ui.selectable_label(self.selected == Some(i), format!("{}  ({})", c.name, c.host));
                            if r.clicked() {
                                pick = Some((c.id.clone(), false));
                            }
                            if r.double_clicked() {
                                pick = Some((c.id.clone(), true));
                            }
                        }
                    });
                }
            });
            if let Some((id, connect)) = pick {
                self.select(&id);
                if connect {
                    self.connect();
                }
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            let e = &mut self.edit;
            egui::Grid::new("form").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                ui.label("Naam");
                ui.text_edit_singleline(&mut e.name);
                ui.end_row();
                ui.label("Map");
                ui.text_edit_singleline(&mut e.folder);
                ui.end_row();
                ui.label("Host");
                ui.text_edit_singleline(&mut e.host);
                ui.end_row();
                ui.label("Poort");
                ui.add(egui::DragValue::new(&mut e.port).range(1..=65535));
                ui.end_row();
                ui.label("Domein");
                ui.text_edit_singleline(&mut e.domain);
                ui.end_row();
                ui.label("Gebruiker");
                ui.text_edit_singleline(&mut e.username);
                ui.end_row();
                ui.label("Wachtwoord");
                ui.add(egui::TextEdit::singleline(&mut e.password).password(true));
                ui.end_row();
                ui.label("Schaal");
                egui::ComboBox::from_id_salt("scale").selected_text(format!("{}%", e.scale)).show_ui(ui, |ui| {
                    for s in [100, 125, 150, 175, 200, 250, 300] {
                        ui.selectable_value(&mut e.scale, s, format!("{s}%"));
                    }
                });
                ui.end_row();
                ui.label("Opties");
                ui.vertical(|ui| {
                    ui.checkbox(&mut e.dynamic_resolution, "Dynamische resolutie");
                    ui.checkbox(&mut e.smart_sizing, "Smart sizing");
                    ui.checkbox(&mut e.fullscreen, "Volledig scherm");
                    ui.checkbox(&mut e.multimon, "Meerdere monitoren");
                });
                ui.end_row();
                ui.label("Notities");
                ui.add(egui::TextEdit::multiline(&mut e.notes).desired_rows(3));
                ui.end_row();
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("💾 Opslaan").clicked() {
                    self.save();
                }
                if ui.add_enabled(self.selected.is_some(), egui::Button::new("🗑 Verwijderen")).clicked() {
                    self.delete();
                }
                if ui.add_enabled(!self.edit.host.is_empty(), egui::Button::new("▶ Verbinden")).clicked() {
                    self.connect();
                }
            });
            ui.add_space(6.0);
            ui.label(&self.status);
        });
    }

    fn save(&mut self) {
        if self.edit.name.trim().is_empty() {
            self.edit.name = self.edit.host.clone();
        }
        let Some(s) = &self.store else { return };
        match s.save(&mut self.edit) {
            Ok(()) => {
                self.status = "Opgeslagen (versleuteld).".into();
                let id = self.edit.id.clone();
                self.reload();
                self.select(&id);
            }
            Err(e) => self.status = e.to_string(),
        }
    }

    fn delete(&mut self) {
        let Some(s) = &self.store else { return };
        if let Err(e) = s.delete(&self.edit.id) {
            self.status = e.to_string();
            return;
        }
        self.selected = None;
        self.edit = Connection::default();
        self.reload();
        self.status = "Verwijderd.".into();
    }

    fn connect(&mut self) {
        self.status = match launch::launch(&self.edit) {
            Ok(()) => format!("Verbinden met {}…", self.edit.host),
            Err(e) => e.to_string(),
        };
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.store.is_some() {
            self.main_ui(ui);
        } else {
            self.unlock_ui(ui);
        }
    }
}

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 560.0]).with_title("RDP Manager"),
        ..Default::default()
    };
    eframe::run_native("RDP Manager", opts, Box::new(|_cc| Ok(Box::new(App::new()))))
}
