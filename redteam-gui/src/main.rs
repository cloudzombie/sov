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

struct RedTeamApp {
    // In-process battery: attack a private replica of consensus.
    results: Arc<Mutex<Option<Vec<sov_redteam::Outcome>>>>,
    running: Arc<AtomicBool>,
    // Live front-door probe: submit adversarial txs to a REAL node's RPC.
    target: String,
    live_report: Arc<Mutex<Option<sov_redteam::LiveReport>>>,
    live_running: Arc<AtomicBool>,
    // Live back-door probe: join P2P as a hostile peer and gossip forged blocks/txs.
    backdoor_report: Arc<Mutex<Option<sov_redteam::P2pReport>>>,
    backdoor_running: Arc<AtomicBool>,
    themed: bool,
}

impl Default for RedTeamApp {
    fn default() -> Self {
        Self {
            results: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            target: "127.0.0.1:8645".to_string(),
            live_report: Arc::new(Mutex::new(None)),
            live_running: Arc::new(AtomicBool::new(false)),
            backdoor_report: Arc::new(Mutex::new(None)),
            backdoor_running: Arc::new(AtomicBool::new(false)),
            themed: false,
        }
    }
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

    /// Fire the live front-door probe at `self.target`, off the UI thread.
    fn run_live(&self) {
        if self.live_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let report = Arc::clone(&self.live_report);
        let running = Arc::clone(&self.live_running);
        std::thread::spawn(move || {
            let r = sov_redteam::probe_frontdoor(&target);
            if let Ok(mut slot) = report.lock() {
                *slot = Some(r);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Clear every result panel so the app returns to its initial state. Disabled while
    /// any probe is running (we don't interrupt a live attack mid-flight).
    fn reset(&self) {
        if let Ok(mut r) = self.results.lock() {
            *r = None;
        }
        if let Ok(mut r) = self.live_report.lock() {
            *r = None;
        }
        if let Ok(mut r) = self.backdoor_report.lock() {
            *r = None;
        }
    }

    /// Fire the live back-door probe at `self.target`, off the UI thread.
    fn run_backdoor(&self) {
        if self.backdoor_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let report = Arc::clone(&self.backdoor_report);
        let running = Arc::clone(&self.backdoor_running);
        std::thread::spawn(move || {
            let r = sov_redteam::probe_backdoor(&target);
            if let Ok(mut slot) = report.lock() {
                *slot = Some(r);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// One attack card: left accent, name + detail, and a verdict chip on the right.
    fn outcome_row(
        ui: &mut egui::Ui,
        name: &str,
        verdict: sov_redteam::Verdict,
        detail: &str,
        accent: Color32,
    ) {
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
                    ui.label(RichText::new("▎").size(22.0).color(accent));
                    ui.vertical(|ui| {
                        ui.label(RichText::new(name).strong().monospace().size(13.5));
                        ui.label(RichText::new(detail).size(11.5).color(MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new(chip).size(11.0).strong().monospace().color(chip_c));
                    });
                });
            });
        ui.add_space(5.0);
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
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let any_busy = self.running.load(Ordering::SeqCst)
                    || self.live_running.load(Ordering::SeqCst)
                    || self.backdoor_running.load(Ordering::SeqCst);
                let btn = egui::Button::new(RichText::new("↺ Reset").size(13.0).color(INK))
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, BORDER))
                    .min_size(egui::vec2(78.0, 26.0));
                if ui.add_enabled(!any_busy, btn).on_hover_text("Clear all results and start over").clicked() {
                    self.reset();
                }
            });
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

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(12.0);
        self.live_section(ui);
    }

    /// The live front-door probe: point at a running node and submit adversarial txs
    /// that are rejected at admission (nothing lands on the chain).
    fn live_section(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("⌁ Live front-door probe").size(19.0).strong().color(PQ));
        ui.label(
            RichText::new(
                "Attack a REAL running node the only way an outsider can — through \
                 sov_submitTransaction. Every probe is designed to be REJECTED at admission, \
                 so nothing lands in the mempool: no tx, no fee, no state change.",
            )
            .size(12.0)
            .color(MUTED),
        );
        ui.add_space(10.0);

        let live_running = self.live_running.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            ui.label(RichText::new("node RPC").size(12.0).color(MUTED));
            ui.add_enabled(
                !live_running,
                egui::TextEdit::singleline(&mut self.target)
                    .desired_width(210.0)
                    .hint_text("host:port"),
            );
            let label = if live_running { "⌁ probing…" } else { "⌁ Probe front door" };
            let btn = egui::Button::new(RichText::new(label).strong().color(Color32::from_rgb(17, 16, 13)))
                .fill(PQ)
                .min_size(egui::vec2(150.0, 30.0));
            if ui.add_enabled(!live_running, btn).clicked() {
                self.run_live();
            }
            if live_running {
                ui.spinner();
            }
        });
        if live_running {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(150));
        }
        ui.add_space(12.0);

        let Ok(guard) = self.live_report.lock() else {
            return;
        };
        let Some(report) = guard.as_ref() else {
            if !live_running {
                ui.label(
                    RichText::new("Enter a node's RPC address and probe its front door.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        };

        if !report.reachable {
            egui::Frame::none()
                .fill(SURFACE)
                .rounding(Rounding::same(10.0))
                .stroke(Stroke::new(1.0, alpha(THREAT, 120)))
                .inner_margin(Margin::symmetric(16.0, 13.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("UNREACHABLE").size(16.0).strong().color(THREAT));
                    ui.label(
                        RichText::new(format!(
                            "Could not reach {} — is the node running with RPC exposed?",
                            report.target
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                });
            return;
        }

        // connectivity + identity banner
        let chain = report.chain_id.as_deref().unwrap_or("unknown");
        let height = report.height.map(|h| h.to_string()).unwrap_or_else(|| "?".into());
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(10.0))
            .stroke(Stroke::new(1.0, alpha(if report.is_mainnet { GOLD } else { PQ }, 120)))
            .inner_margin(Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("● connected").size(12.0).strong().color(HOLD));
                    ui.add_space(14.0);
                    ui.label(RichText::new(&report.target).size(12.0).monospace().color(INK));
                    ui.add_space(14.0);
                    if report.is_mainnet {
                        ui.label(RichText::new("LIVE MAINNET").size(12.0).strong().monospace().color(GOLD));
                    } else {
                        ui.label(RichText::new(chain).size(12.0).monospace().color(PQ));
                    }
                    ui.add_space(14.0);
                    ui.label(RichText::new(format!("height {height}")).size(12.0).monospace().color(MUTED));
                });
            });
        ui.add_space(10.0);

        let admitted = report
            .outcomes
            .iter()
            .filter(|o| o.verdict == sov_redteam::Verdict::Vulnerable)
            .count();
        ui.label(
            RichText::new(if admitted == 0 {
                "FRONT DOOR HELD — every adversarial tx rejected before admission"
            } else {
                "AN ADVERSARIAL TX WAS ADMITTED"
            })
            .size(14.0)
            .strong()
            .color(if admitted == 0 { HOLD } else { THREAT }),
        );

        // No-residue proof: the mempool must be unchanged if nothing was admitted.
        if let (Some(b), Some(a)) = (report.mempool_before, report.mempool_after) {
            let ok = report.no_residue();
            ui.label(
                RichText::new(format!(
                    "mempool {b} → {a}  ·  {}",
                    if ok { "no residue — nothing landed" } else { "RESIDUE — a tx was admitted!" }
                ))
                .size(11.5)
                .monospace()
                .color(if ok { HOLD } else { THREAT }),
            );
        }
        ui.add_space(8.0);

        // Group the probes by class (crypto / authz / encoding / rpc).
        let mut last = "";
        for o in &report.outcomes {
            if o.category != last {
                ui.add_space(7.0);
                ui.label(RichText::new(o.category.to_uppercase()).size(11.0).strong().monospace().color(PQ));
                last = o.category;
            }
            Self::outcome_row(ui, o.name, o.verdict, &o.detail, PQ);
        }

        drop(guard);
        ui.add_space(20.0);
        ui.separator();
        ui.add_space(12.0);
        self.backdoor_section(ui);
    }

    /// The live back-door probe: join the P2P network as a hostile peer and gossip forged
    /// blocks/txs over the encrypted wire, proving the node's tip never adopts them.
    fn backdoor_section(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("⛒ Live back-door probe").size(19.0).strong().color(THREAT));
        ui.label(
            RichText::new(
                "Join the P2P network as a HOSTILE peer and gossip forged blocks + txs over the \
                 encrypted Noise-XX + ML-KEM wire — the nation-state surface. No wire-forged block \
                 can carry valid RandomX PoW, so each is rejected at the seal or parent gate and the \
                 tip never moves; after a few the node BANS us. Nothing lands.",
            )
            .size(12.0)
            .color(MUTED),
        );
        ui.add_space(10.0);

        let running = self.backdoor_running.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            ui.label(RichText::new("node").size(12.0).color(MUTED));
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.target).desired_width(210.0).hint_text("host:port (RPC)"),
            );
            let label = if running { "⛒ attacking P2P…" } else { "⛒ Probe back door" };
            let btn = egui::Button::new(RichText::new(label).strong().color(Color32::from_rgb(17, 16, 13)))
                .fill(THREAT)
                .min_size(egui::vec2(150.0, 30.0));
            if ui.add_enabled(!running, btn).clicked() {
                self.run_backdoor();
            }
            if running {
                ui.spinner();
            }
        });
        if running {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }
        ui.add_space(12.0);

        let Ok(guard) = self.backdoor_report.lock() else {
            return;
        };
        let Some(report) = guard.as_ref() else {
            if !running {
                ui.label(
                    RichText::new("Point it at a node to gossip forged blocks over the real wire.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        };

        if let Some(err) = &report.error {
            egui::Frame::none()
                .fill(SURFACE)
                .rounding(Rounding::same(10.0))
                .stroke(Stroke::new(1.0, alpha(GOLD, 120)))
                .inner_margin(Margin::symmetric(16.0, 12.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("could not run").size(14.0).strong().color(GOLD));
                    ui.label(RichText::new(err).size(12.0).color(MUTED));
                });
            return;
        }

        // connectivity + identity banner
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(10.0))
            .stroke(Stroke::new(1.0, alpha(if report.is_mainnet { GOLD } else { THREAT }, 120)))
            .inner_margin(Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (txt, col) = if report.authenticated {
                        ("● hostile peer authenticated", HOLD)
                    } else {
                        ("○ not authenticated", THREAT)
                    };
                    ui.label(RichText::new(txt).size(12.0).strong().color(col));
                    ui.add_space(12.0);
                    ui.label(RichText::new(&report.p2p_target).size(12.0).monospace().color(INK));
                    ui.add_space(12.0);
                    if report.is_mainnet {
                        ui.label(RichText::new("LIVE MAINNET").size(12.0).strong().monospace().color(GOLD));
                    }
                });
                if let (Some((hb, _)), Some((ha, _))) = (&report.head_before, &report.head_after) {
                    let moved = ha != hb;
                    ui.label(
                        RichText::new(format!(
                            "head {hb} → {ha}  ·  {}",
                            if moved { "advanced only by the node's own honest mining" } else { "tip unmoved" }
                        ))
                        .size(11.5)
                        .monospace()
                        .color(HOLD),
                    );
                }
                if report.ejected {
                    ui.label(RichText::new("the node BANNED our peer — attacker ejected").size(11.5).strong().color(HOLD));
                }
            });
        ui.add_space(10.0);

        let mut last = "";
        for o in &report.outcomes {
            if o.category != last {
                ui.add_space(7.0);
                ui.label(RichText::new(o.category.to_uppercase()).size(11.0).strong().monospace().color(THREAT));
                last = o.category;
            }
            Self::outcome_row(ui, o.name, o.verdict, &o.detail, THREAT);
        }
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
