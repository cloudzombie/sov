//! **SOV Red Team** — a STANDALONE desktop application for the adversarial harness.
//!
//! This is its OWN app, deliberately separate from the wallet / node daemon. It reuses
//! the `sov-redteam` engine library (`run_all()`) — the exact same attacks the CLI runs
//! — and renders them as a live security console. Run it, hit "Run red team", and watch
//! it build a real in-process chain and attack the actual consensus code.
//!
//!   cargo run -p sov-redteam-gui        (or: sov-redteam-gui)

#![forbid(unsafe_code)]
// egui's API is uniformly f32; the fallback on float literals is intentional here.
#![allow(unknown_lints)]
#![allow(float_literal_f32_fallback)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui::{self, Color32, Margin, RichText, Rounding, Stroke};

// ── palette (gold-on-black security console) ────────────────────────────────
const GROUND: Color32 = Color32::from_rgb(10, 12, 9);
const PANEL: Color32 = Color32::from_rgb(16, 19, 9);
const SURFACE: Color32 = Color32::from_rgb(22, 26, 16);
const BORDER: Color32 = Color32::from_rgb(40, 44, 30);
const INK: Color32 = Color32::from_rgb(233, 229, 214);
const MUTED: Color32 = Color32::from_rgb(141, 139, 121);
const GOLD: Color32 = Color32::from_rgb(230, 189, 84);
const HOLD: Color32 = Color32::from_rgb(99, 211, 154);
const THREAT: Color32 = Color32::from_rgb(232, 98, 74);
const PQ: Color32 = Color32::from_rgb(125, 176, 244);

fn alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

#[derive(Default)]
struct RedTeamApp {
    results: Arc<Mutex<Option<Vec<sov_redteam::Outcome>>>>,
    running: Arc<AtomicBool>,
    themed: bool,
}

impl RedTeamApp {
    /// Kick the harness off the UI thread and publish its outcomes when done.
    fn run(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let results = Arc::clone(&self.results);
        let running = Arc::clone(&self.running);
        std::thread::spawn(move || {
            let outcomes = sov_redteam::run_all();
            if let Ok(mut slot) = results.lock() {
                *slot = Some(outcomes);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    fn theme(&mut self, ctx: &egui::Context) {
        if self.themed {
            return;
        }
        self.themed = true;
        let mut v = egui::Visuals::dark();
        v.override_text_color = Some(INK);
        v.panel_fill = GROUND;
        v.window_fill = GROUND;
        v.extreme_bg_color = GROUND;
        ctx.set_visuals(v);
    }
}

impl eframe::App for RedTeamApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.theme(ctx);
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(GROUND).inner_margin(Margin::symmetric(22.0, 18.0)))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.render(ui));
            });
    }
}

impl RedTeamApp {
    fn render(&mut self, ui: &mut egui::Ui) {
        ui.set_max_width(720.0);

        // ── masthead ──
        ui.horizontal(|ui| {
            ui.label(RichText::new("⚔ SOV Red Team").size(26.0).strong().color(GOLD));
        });
        ui.label(
            RichText::new("adversarial harness · attacks the real consensus code, in-process")
                .size(12.5)
                .color(MUTED),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Builds a real chain and throws a battery of attacks at produce_block / \
                 import_block — the same path a node runs. Each is judged DEFENDED or VULNERABLE. \
                 Standalone: this is not the wallet.",
            )
            .size(12.5)
            .color(MUTED),
        );
        ui.add_space(12.0);

        // ── run button ──
        let running = self.running.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            let label = if running {
                "⚔ attacking consensus…"
            } else {
                "⚔ Run red team"
            };
            let btn = egui::Button::new(RichText::new(label).strong().color(Color32::from_rgb(17, 16, 13)))
                .fill(GOLD)
                .min_size(egui::vec2(180.0, 34.0));
            if ui.add_enabled(!running, btn).clicked() {
                self.run();
            }
            if running {
                ui.spinner();
            }
        });
        if running {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(120));
        }
        ui.add_space(14.0);

        // ── results ──
        let results: Option<Vec<(&'static str, &'static str, sov_redteam::Verdict, String)>> = self
            .results
            .lock()
            .ok()
            .and_then(|g| {
                g.as_ref().map(|v| {
                    v.iter()
                        .map(|o| (o.category, o.name, o.verdict, o.detail.clone()))
                        .collect()
                })
            });
        let Some(results) = results else {
            if !running {
                ui.label(
                    RichText::new("Press “Run red team” to attack the chain live.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        };

        let total = results.len();
        let defended = results
            .iter()
            .filter(|(_, _, v, _)| *v == sov_redteam::Verdict::Defended)
            .count();
        let vulnerable = results
            .iter()
            .filter(|(_, _, v, _)| *v == sov_redteam::Verdict::Vulnerable)
            .count();
        let classes = {
            let mut seen = Vec::new();
            for (c, ..) in &results {
                if !seen.contains(c) {
                    seen.push(*c);
                }
            }
            seen.len()
        };
        let clear = vulnerable == 0;

        // verdict banner
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(12.0))
            .stroke(Stroke::new(1.0, alpha(if clear { HOLD } else { THREAT }, 110)))
            .inner_margin(Margin::symmetric(18.0, 15.0))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(if clear {
                        "EVERY DEFENSE HELD"
                    } else {
                        "VULNERABILITIES FOUND"
                    })
                    .size(24.0)
                    .strong()
                    .color(if clear { HOLD } else { THREAT }),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let stat = |ui: &mut egui::Ui, n: usize, label: &str, c: Color32| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(n.to_string()).size(26.0).strong().monospace().color(c));
                            ui.label(RichText::new(label).size(10.0).color(MUTED));
                        });
                    };
                    stat(ui, total, "ATTACKS", GOLD);
                    ui.add_space(22.0);
                    stat(ui, defended, "DEFENDED", HOLD);
                    ui.add_space(22.0);
                    stat(ui, vulnerable, "VULNERABLE", THREAT);
                    ui.add_space(22.0);
                    stat(ui, classes, "CLASSES", INK);
                });
            });
        ui.add_space(14.0);

        // attack rows, grouped by class
        let mut last = "";
        for (cat, name, verdict, detail) in &results {
            if *cat != last {
                ui.add_space(9.0);
                ui.label(RichText::new(cat.to_uppercase()).size(11.0).strong().monospace().color(GOLD));
                last = cat;
            }
            let is_pq = *cat == "post-quantum";
            let (chip, chip_c) = match verdict {
                sov_redteam::Verdict::Defended => ("✓ DEFENDED", HOLD),
                sov_redteam::Verdict::Vulnerable => ("✗ VULNERABLE", THREAT),
                sov_redteam::Verdict::Info => ("• INFO", GOLD),
            };
            egui::Frame::none()
                .fill(PANEL)
                .rounding(Rounding::same(8.0))
                .stroke(Stroke::new(1.0, BORDER))
                .inner_margin(Margin::symmetric(13.0, 10.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("▎").size(22.0).color(if is_pq { PQ } else { THREAT }));
                        ui.vertical(|ui| {
                            ui.label(RichText::new(*name).strong().monospace().size(13.5));
                            ui.label(RichText::new(detail).size(11.5).color(MUTED));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(chip).size(11.0).strong().monospace().color(chip_c));
                        });
                    });
                });
            ui.add_space(5.0);
        }

        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "Honest scope: we can't run Shor's / Grover's or forge BLAKE3 — this proves the \
                 chain fails CLOSED. The hybrid signature needs BOTH halves, so a future break of \
                 Ed25519 alone still leaves ML-DSA-65 (FIPS-204) stopping the forgery.",
            )
            .size(11.0)
            .color(MUTED)
            .italics(),
        );
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 940.0])
            .with_min_inner_size([560.0, 480.0])
            .with_title("SOV Red Team"),
        ..Default::default()
    };
    eframe::run_native(
        "SOV Red Team",
        options,
        Box::new(|_cc| Ok(Box::<RedTeamApp>::default())),
    )
}
