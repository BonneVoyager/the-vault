//! Asset source: gpui-component's default icons, the few extra Lucide icons we use, and
//! the app icon raster and unlock wheel shown on the unlock screen.

use std::borrow::Cow;

use gpui::{AssetSource, Result, SharedString};

gpui_kit_assets::icon_assets!(
    ExtraIcons,
    [
        Lock,
        KeyRound,
        StickyNote,
        CreditCard,
        IdCard,
        Tag,
        LayoutList,
        GripVertical,
        WandSparkles,
        FingerprintPattern,
        ScanQrCode,
        Trash,
        // Item icon symbols (icon::SYMBOLS) not in gpui-kit's default set.
        Landmark,
        Wallet,
        ShoppingCart,
        Gift,
        Mail,
        MessageCircle,
        Shield,
        Users,
        House,
        Briefcase,
        GraduationCap,
        Cloud,
        Server,
        Database,
        Code,
        Bug,
        Wifi,
        Smartphone,
        Gamepad2,
        Music,
        Film,
        Camera,
        Image,
        MapPin,
        Car,
        Plane,
        Coffee
    ]
);

/// Asset path of the app icon raster (`img(APP_ICON)`): 256 px, drawn at 128 pt so it is
/// sharp on Retina. Rendered from `assets/icon/vault.svg`.
pub const APP_ICON: &str = "icon/vault-256.png";
/// The same raster without the wheel's spokes, shown while an unlock runs.
pub const APP_ICON_SPOKELESS: &str = "icon/vault-256-spokeless.png";
/// The six spokes as an SVG mask (`svg().path(APP_ICON_WHEEL)`), rotated over
/// [`APP_ICON_SPOKELESS`] while an unlock runs. Built by `assets/icon/build-unlock-wheel.sh`.
pub const APP_ICON_WHEEL: &str = "icon/wheel.svg";

static EMBEDDED: [(&str, &[u8]); 3] = [
    (
        APP_ICON,
        include_bytes!("../../../assets/icon/vault-256.png"),
    ),
    (
        APP_ICON_SPOKELESS,
        include_bytes!("../../../assets/icon/vault-256-spokeless.png"),
    ),
    (
        APP_ICON_WHEEL,
        include_bytes!("../../../assets/icon/wheel.svg"),
    ),
];

/// The app icon, then our extra icons, then gpui-kit's default component icons.
pub struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some((_, bytes)) = EMBEDDED.iter().find(|(p, _)| *p == path) {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        // Brand logos are generated from the bundled pack on demand; gpui caches the
        // rasterised tile per path and size, so this runs once per logo and size.
        if let Some(slug) = path
            .strip_prefix(crate::icon::BRAND_ASSET_PREFIX)
            .and_then(|p| p.strip_suffix(".svg"))
        {
            return Ok(crate::icon::brand_svg(slug).map(|svg| Cow::Owned(svg.into_bytes())));
        }
        if let Some(bytes) = ExtraIcons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit_assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit_assets::Assets.list(path)?;
        paths.extend(ExtraIcons.list(path)?);
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
        let spokeless = AppAssets
            .load(APP_ICON_SPOKELESS)
            .unwrap()
            .expect("embedded");
        assert_eq!(&spokeless[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(spokeless[16..24], bytes[16..24], "same size as the icon");
        let wheel = AppAssets.load(APP_ICON_WHEEL).unwrap().expect("embedded");
        let wheel = std::str::from_utf8(&wheel).unwrap();
        assert!(wheel.starts_with("<svg"));
        assert!(wheel.len() < 2048, "a small vector, not a frame animation");
        let brand = AppAssets
            .load("brand/github.svg")
            .unwrap()
            .expect("brand logo");
        assert!(brand.starts_with(b"<svg"));
        assert!(AppAssets.load("brand/no-such-brand.svg").unwrap().is_none());
        let listed = AppAssets.list("icon/").unwrap();
        for path in [APP_ICON_SPOKELESS, APP_ICON_WHEEL] {
            assert!(listed.iter().any(|p| p == path), "{path} listed");
        }
    }
}
