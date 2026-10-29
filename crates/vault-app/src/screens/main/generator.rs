//! Password generator popover content (specs/05-ui.md §2.4): Password / Passphrase tabs,
//! tinted monospace preview, length or word-count slider, class toggles, Regenerate,
//! Copy, and "Use" when opened from a password field.
//!
//! The spec and the preview live in `AppState::generator`; this view only owns the two
//! slider states, which gpui-component keeps as entities.

use gpui::{
    AppContext as _, Context, Entity, HighlightStyle, IntoElement, ParentElement as _, Render,
    Styled as _, StyledText, Subscription, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::checkbox::Checkbox;
use gpui_component::slider::{Slider, SliderEvent, SliderState};
use gpui_component::tab::{Tab, TabBar};
use gpui_component::{ActiveTheme as _, Icon, Selectable as _, Sizable as _};
use gpui_kit_assets::IconName;
use vault_core::{ExposeSecret as _, strength_bits};

use crate::state::{
    AppState, CharClass, GenTab, GeneratorTarget, LENGTH_RANGE, SEPARATORS, WORDS_RANGE,
};
use crate::ui;

pub struct GeneratorView {
    state: Entity<AppState>,
    length: Entity<SliderState>,
    words: Entity<SliderState>,
    _subscriptions: Vec<Subscription>,
}

impl GeneratorView {
    pub fn new(state: Entity<AppState>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (length, words) = {
            let g = &state.read(cx).generator;
            (g.password.length, g.passphrase.words)
        };
        let slider =
            |range: &std::ops::RangeInclusive<usize>, value: usize, cx: &mut Context<Self>| {
                let (min, max) = (*range.start() as f32, *range.end() as f32);
                cx.new(|_| {
                    SliderState::new()
                        .min(min)
                        .max(max)
                        .step(1.)
                        .default_value(value as f32)
                })
            };
        let length = slider(&LENGTH_RANGE, length, cx);
        let words = slider(&WORDS_RANGE, words, cx);
        let subscriptions = vec![
            cx.subscribe_in(&length, window, |this, _, ev: &SliderEvent, _, cx| {
                let (SliderEvent::Change(v) | SliderEvent::Release(v)) = ev;
                let n = v.end().round() as usize;
                this.state
                    .update(cx, |s, cx| s.update_generator(cx, |g| g.set_length(n)));
            }),
            cx.subscribe_in(&words, window, |this, _, ev: &SliderEvent, _, cx| {
                let (SliderEvent::Change(v) | SliderEvent::Release(v)) = ev;
                let n = v.end().round() as usize;
                this.state
                    .update(cx, |s, cx| s.update_generator(cx, |g| g.set_words(n)));
            }),
        ];
        Self {
            state,
            length,
            words,
            _subscriptions: subscriptions,
        }
    }

    fn check(
        &self,
        id: &'static str,
        label: &'static str,
        checked: bool,
        f: fn(&mut crate::state::Generator),
    ) -> Checkbox {
        let state = self.state.clone();
        Checkbox::new(id)
            .label(label)
            .checked(checked)
            .on_click(move |_, _, cx| state.update(cx, |s, cx| s.update_generator(cx, f)))
    }
}

/// Preview text with digits and symbols tinted (not colour alone: the monospace glyphs
/// themselves differ, and the strength label sits underneath).
fn tinted(text: String, digit: gpui::Hsla, symbol: gpui::Hsla) -> StyledText {
    let mut highlights = Vec::new();
    for (i, c) in text.char_indices() {
        let color = if c.is_ascii_digit() {
            digit
        } else if !c.is_alphanumeric() {
            symbol
        } else {
            continue;
        };
        highlights.push((
            i..i + c.len_utf8(),
            HighlightStyle {
                color: Some(color),
                ..Default::default()
            },
        ));
    }
    StyledText::new(text).with_highlights(highlights)
}

impl Render for GeneratorView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let s = self.state.read(cx);
        let g = &s.generator;
        let theme = cx.theme();
        let preview = g.preview().expose_secret().to_owned();
        let bits = strength_bits(&preview);
        let can_use = matches!(s.generator_target, Some(GeneratorTarget::Field(_)));
        let tab = g.tab;
        let state = self.state.clone();

        let tabs = TabBar::new("generator-tabs")
            .segmented()
            .small()
            .selected_index(match tab {
                GenTab::Password => 0,
                GenTab::Passphrase => 1,
            })
            .child(Tab::new().label("Password"))
            .child(Tab::new().label("Passphrase"))
            .on_click({
                let state = state.clone();
                move |ix, _, cx| {
                    let tab = if *ix == 0 {
                        GenTab::Password
                    } else {
                        GenTab::Passphrase
                    };
                    state.update(cx, |s, cx| s.update_generator(cx, |g| g.set_tab(tab)));
                }
            });

        let preview_box = div()
            .p(px(10.))
            .rounded(theme.radius)
            .bg(theme.secondary)
            .min_h(px(44.))
            .font_family(theme.mono_font_family.clone())
            .text_lg()
            .whitespace_normal()
            .child(tinted(preview, theme.primary, theme.danger));

        let controls = match tab {
            GenTab::Password => {
                let p = &g.password;
                ui::v_flex()
                    .gap(px(8.))
                    .child(ui::muted(format!("Length  {}", p.length), cx))
                    .child(Slider::new(&self.length).accessibility_label("Password length"))
                    .child(
                        ui::h_flex()
                            .gap(px(12.))
                            .flex_wrap()
                            .child(self.check("gen-lower", "a–z", p.lower, |g| {
                                g.toggle(CharClass::Lower)
                            }))
                            .child(self.check("gen-upper", "A–Z", p.upper, |g| {
                                g.toggle(CharClass::Upper)
                            }))
                            .child(self.check("gen-digits", "0–9", p.digits, |g| {
                                g.toggle(CharClass::Digits)
                            }))
                            .child(self.check("gen-symbols", "!@#", p.symbols, |g| {
                                g.toggle(CharClass::Symbols)
                            })),
                    )
                    .child(self.check(
                        "gen-ambiguous",
                        "Exclude look-alikes (0 O 1 l I)",
                        p.exclude_ambiguous,
                        |g| g.toggle(CharClass::ExcludeAmbiguous),
                    ))
            }
            GenTab::Passphrase => {
                let p = &g.passphrase;
                let separators = SEPARATORS.iter().map(|sep| {
                    let sep = *sep;
                    let state = state.clone();
                    let label = if sep == ' ' {
                        "space".to_owned()
                    } else {
                        sep.to_string()
                    };
                    Button::new(("gen-sep", sep as u32 as usize))
                        .small()
                        .label(label)
                        .selected(p.separator == sep)
                        .when(p.separator == sep, |b| b.primary())
                        .on_click(move |_, _, cx| {
                            state.update(cx, |s, cx| {
                                s.update_generator(cx, |g| g.set_separator(sep))
                            });
                        })
                });
                ui::v_flex()
                    .gap(px(8.))
                    .child(ui::muted(format!("Words  {}", p.words), cx))
                    .child(Slider::new(&self.words).accessibility_label("Number of words"))
                    .child(
                        ui::h_flex()
                            .gap(px(4.))
                            .child(ui::muted("Separator", cx).mr(px(4.)))
                            .children(separators),
                    )
                    .child(
                        ui::h_flex()
                            .gap(px(12.))
                            .child(
                                self.check("gen-capitalize", "Capitalize", p.capitalize, |g| {
                                    g.toggle_capitalize()
                                }),
                            )
                            .child(self.check("gen-number", "Add a number", p.number, |g| {
                                g.toggle_number()
                            })),
                    )
            }
        };

        let footer = ui::h_flex()
            .gap(px(6.))
            .child(
                Button::new("gen-regenerate")
                    .ghost()
                    .small()
                    .icon(Icon::new(IconName::RefreshCw))
                    .label("Regenerate")
                    .on_click({
                        let state = state.clone();
                        move |_, _, cx| {
                            state.update(cx, |s, cx| s.update_generator(cx, |g| g.regenerate()))
                        }
                    }),
            )
            .child(div().flex_1())
            .child(
                Button::new("gen-copy")
                    .small()
                    .icon(Icon::new(IconName::Copy))
                    .label("Copy")
                    .on_click({
                        let state = state.clone();
                        move |_, _, cx| state.update(cx, |s, cx| s.copy_generated(cx))
                    }),
            )
            .when(can_use, |row| {
                row.child(
                    Button::new("gen-use")
                        .primary()
                        .small()
                        .label("Use")
                        .on_click(move |_, _, cx| state.update(cx, |s, cx| s.use_generated(cx))),
                )
            });

        ui::v_flex()
            .w(px(360.))
            .gap(px(12.))
            .child(tabs)
            .child(preview_box)
            .child(ui::strength_meter(bits, cx))
            .child(controls)
            .child(footer)
    }
}
