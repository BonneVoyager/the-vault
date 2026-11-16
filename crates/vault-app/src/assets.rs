//! Asset source: the full Lucide catalog of gpui-kit-assets (`AllAssets`, which also holds
//! gpui-component's own icons; the item and field icon pickers search all of it), and the
//! app icon raster and unlock wheel shown on the unlock screen.

use std::borrow::Cow;

use gpui::{AssetSource, Result, SharedString};

/// Asset path of the app icon raster (`img(APP_ICON)`): 256 px, drawn at 128 pt so it is
/// sharp on Retina. Rendered from `assets/icon/vault.svg`.
pub const APP_ICON: &str = "icon/vault-256.png";
/// Twenty-four 256 px frames of the original icon across one 60-degree spoke sector.
/// Frame zero matches [`APP_ICON`] exactly. Built by `assets/icon/build-unlock-wheel.sh`.
pub const APP_ICON_WHEEL_STRIP: &str = "icon/vault-wheel-strip.png";
/// The icon's keyhole (glow, body, highlight) on a transparent background at the icon's
/// 256 px scale, cropped to `screens::unlock::KEYHOLE_*`: the successful-unlock flare.
/// Built by `assets/icon/build-unlock-wheel.sh`.
pub const APP_ICON_KEYHOLE: &str = "icon/vault-keyhole.png";

static EMBEDDED: [(&str, &[u8]); 3] = [
    (
        APP_ICON,
        include_bytes!("../../../assets/icon/vault-256.png"),
    ),
    (
        APP_ICON_WHEEL_STRIP,
        include_bytes!("../../../assets/icon/vault-wheel-strip.png"),
    ),
    (
        APP_ICON_KEYHOLE,
        include_bytes!("../../../assets/icon/vault-keyhole.png"),
    ),
];

/// The app icon rasters, then the whole icon catalog.
pub struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some((_, bytes)) = EMBEDDED.iter().find(|(p, _)| *p == path) {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        gpui_kit_assets::AllAssets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit_assets::AllAssets.list(path)?;
        paths.extend(
            EMBEDDED
                .iter()
                .filter(|(p, _)| p.starts_with(path))
                .map(|(p, _)| SharedString::from(*p)),
        );
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_icon_is_a_256_px_png() {
        let bytes = AppAssets.load(APP_ICON).unwrap().expect("embedded");
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
        // IHDR: width and height, big-endian, at bytes 16..24.
        assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 256);
        assert_eq!(u32::from_be_bytes(bytes[20..24].try_into().unwrap()), 256);
        assert!(
            AppAssets
                .list("icon/")
                .unwrap()
                .iter()
                .any(|p| p == APP_ICON)
        );
        assert!(
            AppAssets.load("icons/lock.svg").unwrap().is_some(),
            "icons still load"
        );
        // The Server and License template icons (05 §2.3) are bundled.
        for icon in [
            gpui_kit_assets::IconName::Server,
            gpui_kit_assets::IconName::FileBadge,
        ] {
            let path = icon.path();
            assert!(AppAssets.load(&path).unwrap().is_some(), "{path}");
        }
        let strip = AppAssets
            .load(APP_ICON_WHEEL_STRIP)
            .unwrap()
            .expect("embedded");
        let original = image::load_from_memory(&bytes).unwrap().to_rgba8();
        let frames = image::load_from_memory(&strip).unwrap().to_rgba8();
        assert_eq!(frames.dimensions(), (256 * 24, 256));
        for y in 0..256 {
            for x in 0..256 {
                assert_eq!(frames.get_pixel(x, y), original.get_pixel(x, y));
            }
        }
        // The whole catalog loads, not only the default set (05 "Icon search").
        for icon in gpui_kit_assets::IconName::ALL {
            let path = icon.path();
            assert!(AppAssets.load(&path).unwrap().is_some(), "{path}");
        }
        let listed = AppAssets.list("icon/").unwrap();
        assert!(listed.iter().any(|p| p == APP_ICON_WHEEL_STRIP));

        let keyhole = AppAssets.load(APP_ICON_KEYHOLE).unwrap().expect("embedded");
        assert_eq!(&keyhole[..8], b"\x89PNG\r\n\x1a\n");
        let (w, h) = crate::screens::unlock::KEYHOLE_SIZE;
        assert_eq!(
            u32::from_be_bytes(keyhole[16..20].try_into().unwrap()),
            2 * w as u32
        );
        assert_eq!(
            u32::from_be_bytes(keyhole[20..24].try_into().unwrap()),
            2 * h as u32
        );
        assert!(keyhole.len() < 32 * 1024, "small overlay");
        // Placed right: the keyhole's body (opaque pixels 3 px inside the opaque area, so
        // not its edge over the flare) matches the icon under it.
        let overlay = image::load_from_memory(&keyhole).unwrap().to_rgba8();
        let (x0, y0) = crate::screens::unlock::KEYHOLE_ORIGIN;
        let (x0, y0) = (2 * x0 as u32, 2 * y0 as u32);
        let opaque = |x: u32, y: u32| overlay.get_pixel_checked(x, y).is_some_and(|p| p[3] == 255);
        let mut body = 0;
        for (x, y, px) in overlay.enumerate_pixels() {
            let inner =
                (0..49).all(|i| opaque((x + i % 7).wrapping_sub(3), (y + i / 7).wrapping_sub(3)));
            if inner {
                assert_eq!(px, original.get_pixel(x0 + x, y0 + y), "keyhole at {x},{y}");
                body += 1;
            }
        }
        assert!(body > 400, "{body} keyhole body pixels");
        assert!(listed.iter().any(|p| p == APP_ICON_KEYHOLE));
    }
}
