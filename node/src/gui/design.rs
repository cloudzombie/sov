//! SOV Station's shared visual language. This module only renders presentation;
//! wallet state, amounts, node status, and action handlers stay with their callers.

use eframe::egui;

/// Mode-aware surfaces and semantic colors. Status always keeps its accompanying
/// label or glyph: color is a secondary signal, never the only one.
pub(super) mod palette {
    use eframe::egui::Color32;
    use std::sync::atomic::{AtomicBool, Ordering};

    static DARK: AtomicBool = AtomicBool::new(true);

    pub fn set_dark(dark: bool) {
        DARK.store(dark, Ordering::Relaxed);
    }

    pub fn is_dark() -> bool {
        DARK.load(Ordering::Relaxed)
    }

    fn pick(dark: Color32, light: Color32) -> Color32 {
        if is_dark() {
            dark
        } else {
            light
        }
    }

    const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
        Color32::from_rgb(r, g, b)
    }

    pub fn bg() -> Color32 {
        pick(rgb(13, 17, 22), rgb(244, 247, 246))
    }

    pub fn panel() -> Color32 {
        pick(rgb(20, 26, 32), rgb(255, 255, 255))
    }

    pub fn surface() -> Color32 {
        pick(rgb(28, 35, 42), rgb(238, 243, 240))
    }

    pub fn surface_hi() -> Color32 {
        pick(rgb(39, 49, 58), rgb(225, 235, 229))
    }

    pub fn field() -> Color32 {
        pick(rgb(13, 19, 24), rgb(249, 251, 250))
    }

    pub fn border() -> Color32 {
        pick(rgb(50, 62, 71), rgb(211, 221, 215))
    }

    pub fn text() -> Color32 {
        pick(rgb(237, 243, 246), rgb(25, 38, 30))
    }

    pub fn text_dim() -> Color32 {
        pick(rgb(169, 182, 192), rgb(85, 102, 94))
    }

    pub fn accent() -> Color32 {
        pick(rgb(152, 231, 122), rgb(40, 112, 54))
    }

    pub fn accent_hi() -> Color32 {
        pick(rgb(181, 244, 153), rgb(29, 96, 45))
    }

    /// Text on the solid primary accent, calibrated for both modes.
    pub fn accent_text() -> Color32 {
        pick(rgb(18, 35, 23), Color32::WHITE)
    }

    pub fn success() -> Color32 {
        pick(rgb(91, 214, 148), rgb(23, 112, 68))
    }

    pub fn error() -> Color32 {
        pick(rgb(255, 128, 139), rgb(181, 47, 67))
    }

    pub fn warning() -> Color32 {
        pick(rgb(231, 192, 111), rgb(141, 103, 29))
    }

    pub fn link() -> Color32 {
        pick(rgb(137, 190, 248), rgb(32, 100, 175))
    }

    /// A witnessed active miner remains gold, distinct from synced green.
    pub fn mining() -> Color32 {
        pick(rgb(247, 197, 80), rgb(150, 107, 6))
    }

    /// Defined in consensus and awaiting activation: neither warning nor failure.
    pub fn dormant() -> Color32 {
        pick(rgb(135, 163, 202), rgb(81, 109, 141))
    }

    /// Unknown data stays a dim em dash rather than appearing as a measured zero.
    pub fn unknown() -> Color32 {
        pick(rgb(114, 129, 140), rgb(114, 126, 119))
    }

    pub fn tint(c: Color32, alpha: u8) -> Color32 {
        Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
    }
}

/// A clear hierarchy: readable body text, quiet labels, and one lead metric.
pub(super) mod ty {
    pub const HERO: f32 = 32.0;
    pub const TITLE: f32 = 22.0;
    pub const SECTION: f32 = 16.0;
    pub const BODY: f32 = 14.0;
    pub const SMALL: f32 = 12.5;
    pub const MICRO: f32 = 11.0;
}

pub(super) mod sp {
    pub const XS: f32 = 2.0;
    pub const S: f32 = 4.0;
    pub const M: f32 = 8.0;
    pub const L: f32 = 12.0;
    pub const XL: f32 = 20.0;
}

/// Tabular figures keep changing values from shifting their neighboring labels.
pub(super) fn num(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).monospace()
}

pub(super) fn num_unknown() -> egui::RichText {
    num("—").color(palette::unknown())
}

pub(super) fn stat(ui: &mut egui::Ui, label: &str, value: Option<&str>, unit: &str, size: f32) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new(label.to_uppercase())
                .size(ty::MICRO)
                .color(palette::text_dim()),
        );
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = sp::S;
            match value {
                Some(v) => ui.label(num(v).size(size).strong().color(palette::text())),
                None => ui.label(num_unknown().size(size)),
            };
            if !unit.is_empty() && value.is_some() {
                ui.label(
                    egui::RichText::new(unit)
                        .size(ty::SMALL)
                        .color(palette::text_dim()),
                );
            }
        });
    });
}

pub(super) fn state_chip(ui: &mut egui::Ui, glyph: &str, word: &str, col: egui::Color32) {
    egui::Frame::none()
        .fill(palette::tint(col, 18))
        .stroke(egui::Stroke::new(1.0, palette::tint(col, 74)))
        .rounding(egui::Rounding::same(20.0))
        .inner_margin(egui::Margin::symmetric(10.0, 5.0))
        .show(ui, |ui| {
            ui.spacing_mut().interact_size.y = 0.0;
            ui.spacing_mut().item_spacing.x = sp::S;
            ui.horizontal(|ui| {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 12.0), egui::Sense::hover());
                let center = rect.center();
                match glyph {
                    "?" => {
                        ui.painter().text(
                            center,
                            egui::Align2::CENTER_CENTER,
                            "?",
                            egui::FontId::proportional(12.0),
                            col,
                        );
                    }
                    "◌" | "○" => {
                        ui.painter()
                            .circle_stroke(center, 3.5, egui::Stroke::new(1.2, col));
                    }
                    "▲" => {
                        ui.painter().add(egui::Shape::convex_polygon(
                            vec![
                                center + egui::vec2(0.0, -4.0),
                                center + egui::vec2(4.0, 3.0),
                                center + egui::vec2(-4.0, 3.0),
                            ],
                            col,
                            egui::Stroke::NONE,
                        ));
                    }
                    _ => {
                        ui.painter().circle_filled(center, 3.5, col);
                    }
                }
                ui.label(
                    egui::RichText::new(word)
                        .size(ty::MICRO)
                        .strong()
                        .color(col),
                );
            });
        });
}

/// The shared card shell; callers retain their contents and interactions.
pub(super) fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(palette::panel())
        .stroke(egui::Stroke::new(1.0, palette::border()))
        .rounding(egui::Rounding::same(14.0))
        .inner_margin(egui::Margin::same(18.0))
}

pub(super) fn section_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(
        egui::RichText::new(title)
            .size(ty::TITLE)
            .strong()
            .color(palette::text()),
    );
    if !subtitle.is_empty() {
        ui.label(
            egui::RichText::new(subtitle)
                .size(ty::SMALL)
                .color(palette::text_dim()),
        );
    }
    ui.add_space(sp::L);
}

pub(super) fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    ui.scope(|ui| {
        // Keep egui's disabled, hover, pressed, and keyboard-focus responses.
        // A hardcoded Button::fill would erase the hover state.
        let widgets = &mut ui.visuals_mut().widgets;
        widgets.inactive.bg_fill = palette::accent();
        widgets.inactive.weak_bg_fill = palette::accent();
        widgets.inactive.bg_stroke = egui::Stroke::NONE;
        widgets.hovered.bg_fill = palette::accent_hi();
        widgets.hovered.weak_bg_fill = palette::accent_hi();
        widgets.hovered.bg_stroke = egui::Stroke::new(1.0, palette::accent_hi());
        widgets.active.bg_fill = palette::accent_hi();
        widgets.active.weak_bg_fill = palette::accent_hi();
        widgets.active.bg_stroke = egui::Stroke::new(1.0, palette::accent_hi());
        ui.add_enabled(
            enabled,
            egui::Button::new(
                egui::RichText::new(label)
                    .size(ty::BODY)
                    .strong()
                    .color(palette::accent_text()),
            )
            .rounding(egui::Rounding::same(9.0))
            .min_size(egui::vec2(108.0, 38.0)),
        )
    })
    .inner
}

/// Apply the same surfaces, focus states, spacing, and type scale to every view.
pub(super) fn install_theme(ctx: &egui::Context, dark: bool) {
    use egui::{FontId, Rounding, Stroke, TextStyle};

    palette::set_dark(dark);
    let mut style = (*ctx.style()).clone();
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let r = Rounding::same(9.0);

    v.widgets.noninteractive.bg_fill = palette::panel();
    v.widgets.noninteractive.weak_bg_fill = palette::panel();
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette::border());
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.noninteractive.rounding = r;

    v.widgets.inactive.bg_fill = palette::surface();
    v.widgets.inactive.weak_bg_fill = palette::surface();
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, palette::border());
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.inactive.rounding = r;

    v.widgets.hovered.bg_fill = palette::surface_hi();
    v.widgets.hovered.weak_bg_fill = palette::surface_hi();
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, palette::accent());
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.hovered.rounding = r;

    v.widgets.active.bg_fill = palette::surface_hi();
    v.widgets.active.weak_bg_fill = palette::surface_hi();
    v.widgets.active.bg_stroke = Stroke::new(1.0, palette::accent_hi());
    // egui also uses this foreground for every RichText::strong heading.
    // Dark text belongs only on solid primary buttons, which set it locally.
    v.widgets.active.fg_stroke = Stroke::new(1.0, palette::text());
    v.widgets.active.rounding = r;
    v.widgets.open = v.widgets.inactive;

    v.selection.bg_fill = palette::tint(palette::accent(), if dark { 45 } else { 32 });
    v.selection.stroke = Stroke::new(1.0, palette::accent_hi());
    v.hyperlink_color = palette::link();
    v.warn_fg_color = palette::warning();
    v.error_fg_color = palette::error();
    v.window_fill = palette::panel();
    v.window_stroke = Stroke::new(1.0, palette::border());
    v.window_rounding = Rounding::same(14.0);
    v.menu_rounding = Rounding::same(10.0);
    v.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 8.0),
        blur: 24.0,
        spread: 0.0,
        color: egui::Color32::from_black_alpha(if dark { 90 } else { 24 }),
    };
    v.popup_shadow = v.window_shadow;
    v.panel_fill = palette::bg();
    v.extreme_bg_color = palette::field();
    v.faint_bg_color = palette::tint(palette::text(), if dark { 5 } else { 3 });
    v.code_bg_color = palette::field();

    style.visuals = v;
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(ty::TITLE));
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(ty::BODY));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(ty::BODY));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(ty::SMALL));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(ty::BODY));
    style.spacing.item_spacing = egui::vec2(sp::M, sp::M);
    style.spacing.button_padding = egui::vec2(sp::L, sp::M);
    style.spacing.interact_size.y = 32.0;
    style.spacing.indent = sp::XL;
    style.spacing.window_margin = egui::Margin::same(18.0);
    ctx.set_style(style);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_strong_text_keeps_the_body_foreground() {
        let ctx = egui::Context::default();
        install_theme(&ctx, true);
        let style = ctx.style();
        assert_eq!(style.visuals.strong_text_color(), palette::text());
        assert_eq!(style.visuals.widgets.active.bg_fill, palette::surface_hi());
    }
}
