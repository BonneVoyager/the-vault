//! System appearance: the user's accent colour and a change notification.

use crate::idle::Subscription;

/// An sRGB colour with components in `0.0..=1.0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgba {
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

/// The user's accent colour (`NSColor.controlAccentColor`) converted to sRGB.
///
/// Returns `None` off the main thread, if the conversion to sRGB fails, or
/// off macOS. When the user picks "Multicolour" in System Settings >
/// Appearance, AppKit reports the default blue, so this returns blue too.
pub fn system_accent_color() -> Option<Rgba> {
    imp::system_accent_color()
}

/// Calls `cb` when AppKit posts `NSSystemColorsDidChangeNotification` on the
/// default notification center, which happens on the main thread when the
/// accent or highlight colour changes. Call [`system_accent_color`] again from
/// the callback to read the new value.
///
/// The observer stays registered until the returned [`Subscription`] is
/// dropped; drop it on the main thread. No-op off macOS.
#[must_use = "dropping the Subscription unregisters the observer"]
pub fn on_system_colors_changed(cb: impl Fn() + Send + 'static) -> Subscription {
    imp::on_system_colors_changed(cb)
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSColor, NSColorSpace, NSSystemColorsDidChangeNotification};
    use objc2_core_foundation::CGFloat;
    use objc2_foundation::{NSNotificationCenter, NSNotificationName};

    use super::Rgba;
    use crate::idle::{Subscription, on_center_notification};

    pub fn system_accent_color() -> Option<Rgba> {
        // Accent colour is read from AppKit appearance state; restrict to the
        // main thread as AppKit's appearance APIs expect.
        let _mtm = MainThreadMarker::new()?;
        let color =
            NSColor::controlAccentColor().colorUsingColorSpace(&NSColorSpace::sRGBColorSpace())?;
        let (mut r, mut g, mut b, mut a): (CGFloat, CGFloat, CGFloat, CGFloat) =
            (0.0, 0.0, 0.0, 0.0);
        // SAFETY: the four pointers are valid, writable, distinct CGFloat
        // locals; `color` is in an RGB colour space (sRGB), which
        // getRed:green:blue:alpha: requires.
        unsafe { color.getRed_green_blue_alpha(&mut r, &mut g, &mut b, &mut a) };
        let c = |v: CGFloat| (v as f32).clamp(0.0, 1.0);
        Some(Rgba {
            r: c(r),
            g: c(g),
            b: c(b),
            a: c(a),
        })
    }

    pub fn on_system_colors_changed(cb: impl Fn() + Send + 'static) -> Subscription {
        // SAFETY: AppKit initialises this extern constant at load time; it is
        // an immutable NSString that lives for the whole process.
        let name: &NSNotificationName = unsafe { NSSystemColorsDidChangeNotification };
        on_center_notification(NSNotificationCenter::defaultCenter(), name, cb)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Rgba;
    use crate::idle::{Subscription, noop_subscription};

    pub fn system_accent_color() -> Option<Rgba> {
        None
    }

    pub fn on_system_colors_changed(_cb: impl Fn() + Send + 'static) -> Subscription {
        noop_subscription()
    }
}
