//! Asset source: gpui-component's default icons, the few extra Lucide icons we use, and
//! the app icon raster shown on the unlock screen.

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
        Trash
    ]
);

/// Asset path of the app icon raster (`img(APP_ICON)`): 256 px, drawn at 128 pt so it is
/// sharp on Retina. Generated from `assets/icon/Vault.icns` (its 128@2x slice).
pub const APP_ICON: &str = "icon/vault-256.png";

static APP_ICON_PNG: &[u8] = include_bytes!("../../../assets/icon/vault-256.png");

/// The app icon, then our extra icons, then gpui-kit's default component icons.
pub struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if path == APP_ICON {
            return Ok(Some(Cow::Borrowed(APP_ICON_PNG)));
        }
        if let Some(bytes) = ExtraIcons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit_assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit_assets::Assets.list(path)?;
        paths.extend(ExtraIcons.list(path)?);
        if APP_ICON.starts_with(path) {
            paths.push(APP_ICON.into());
        }
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
    }
}
