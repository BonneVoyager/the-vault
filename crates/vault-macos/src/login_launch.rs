//! Login-item launch detection (spec 04 §5d).
//!
//! `loginwindow` starts a login item with a `kAEOpenApplication` Apple Event
//! whose `keyAEPropData` parameter is the enum `keyAELaunchedAsLogInItem`.
//! The current Apple Event is only that event while
//! `applicationDidFinishLaunching` is on the stack, so call this once there.

/// Four-char code as AppKit stores it (big-endian bytes in a `u32`).
const fn four_cc(code: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*code)
}

/// `kCoreEventClass`.
const K_CORE_EVENT_CLASS: u32 = four_cc(b"aevt");
/// `kAEOpenApplication`.
const K_AE_OPEN_APPLICATION: u32 = four_cc(b"oapp");
/// `keyAEPropData`.
const KEY_AE_PROP_DATA: u32 = four_cc(b"prdt");
/// `keyAELaunchedAsLogInItem`.
const KEY_AE_LAUNCHED_AS_LOG_IN_ITEM: u32 = four_cc(b"lgit");

/// True when the current Apple Event says the app was started as a login
/// item. False off the main thread, off macOS, with no current event, when
/// the event is not `oapp` or lacks the `lgit` property, and on any error.
pub fn launched_as_login_item() -> bool {
    imp::launched_as_login_item()
}

/// The pure part of the check: an `aevt`/`oapp` event whose `prdt`
/// parameter's enum code is `lgit`.
fn is_login_launch(event_class: u32, event_id: u32, prop_data_enum: Option<u32>) -> bool {
    event_class == K_CORE_EVENT_CLASS
        && event_id == K_AE_OPEN_APPLICATION
        && prop_data_enum == Some(KEY_AE_LAUNCHED_AS_LOG_IN_ITEM)
}

#[cfg(target_os = "macos")]
mod imp {
    use objc2::MainThreadMarker;
    use objc2_foundation::{NSAppleEventDescriptor, NSAppleEventManager};

    use super::{KEY_AE_PROP_DATA, is_login_launch};

    pub fn launched_as_login_item() -> bool {
        if MainThreadMarker::new().is_none() {
            return false;
        }
        NSAppleEventManager::sharedAppleEventManager()
            .currentAppleEvent()
            .is_some_and(|event| event_is_login_launch(&event))
    }

    pub fn event_is_login_launch(event: &NSAppleEventDescriptor) -> bool {
        let prop = event
            .paramDescriptorForKeyword(KEY_AE_PROP_DATA)
            .map(|p| p.enumCodeValue());
        is_login_launch(event.eventClass(), event.eventID(), prop)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn launched_as_login_item() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_cc_matches_the_carbon_constants() {
        assert_eq!(K_CORE_EVENT_CLASS, 0x6165_7674);
        assert_eq!(K_AE_OPEN_APPLICATION, 0x6F61_7070);
        assert_eq!(KEY_AE_PROP_DATA, 0x7072_6474);
        assert_eq!(KEY_AE_LAUNCHED_AS_LOG_IN_ITEM, 0x6C67_6974);
    }

    #[test]
    fn pure_check_needs_all_three_parts() {
        let lgit = Some(KEY_AE_LAUNCHED_AS_LOG_IN_ITEM);
        assert!(is_login_launch(
            K_CORE_EVENT_CLASS,
            K_AE_OPEN_APPLICATION,
            lgit
        ));
        assert!(!is_login_launch(
            K_CORE_EVENT_CLASS,
            K_AE_OPEN_APPLICATION,
            None
        ));
        assert!(!is_login_launch(K_CORE_EVENT_CLASS, four_cc(b"odoc"), lgit));
        assert!(!is_login_launch(
            four_cc(b"misc"),
            K_AE_OPEN_APPLICATION,
            lgit
        ));
        assert!(!is_login_launch(
            K_CORE_EVENT_CLASS,
            K_AE_OPEN_APPLICATION,
            Some(four_cc(b"null"))
        ));
    }

    // libtest worker threads: the main-thread guard (or the stub) says false.
    #[test]
    fn off_main_thread_is_false() {
        assert!(!launched_as_login_item());
    }

    /// Builds a real `NSAppleEventDescriptor` with the given class and id, plus `prop`
    /// as its `prdt` parameter, and runs the same check as [`launched_as_login_item`].
    #[cfg(target_os = "macos")]
    fn event_with(
        event_class: &[u8; 4],
        event_id: &[u8; 4],
        prop: Option<objc2::rc::Retained<objc2_foundation::NSAppleEventDescriptor>>,
    ) -> bool {
        use objc2_foundation::NSAppleEventDescriptor;
        let event = NSAppleEventDescriptor::appleEventWithEventClass_eventID_targetDescriptor_returnID_transactionID(
            four_cc(event_class),
            four_cc(event_id),
            None,
            -1, // kAutoGenerateReturnID
            0,  // kAnyTransactionID
        );
        if let Some(value) = prop {
            event.setParamDescriptor_forKeyword(&value, KEY_AE_PROP_DATA);
        }
        imp::event_is_login_launch(&event)
    }

    #[cfg(target_os = "macos")]
    fn test_event_is_login_launch(
        event_class: &[u8; 4],
        event_id: &[u8; 4],
        prop: Option<&[u8; 4]>,
    ) -> bool {
        use objc2_foundation::NSAppleEventDescriptor;
        let prop = prop.map(|code| NSAppleEventDescriptor::descriptorWithEnumCode(four_cc(code)));
        event_with(event_class, event_id, prop)
    }

    /// A `prdt` that is not an enum (here a string, even one spelling "lgit") is not a
    /// login launch.
    #[cfg(target_os = "macos")]
    #[test]
    fn non_enum_prop_data_is_false() {
        use objc2_foundation::{NSAppleEventDescriptor, NSString};
        let text = NSAppleEventDescriptor::descriptorWithString(&NSString::from_str("lgit"));
        assert!(!event_with(b"aevt", b"oapp", Some(text)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_descriptors_through_the_objc_path() {
        assert!(test_event_is_login_launch(b"aevt", b"oapp", Some(b"lgit")));
        assert!(!test_event_is_login_launch(b"aevt", b"oapp", None));
        assert!(!test_event_is_login_launch(b"aevt", b"oapp", Some(b"xxxx")));
        assert!(!test_event_is_login_launch(b"aevt", b"rapp", Some(b"lgit")));
        assert!(!test_event_is_login_launch(b"core", b"oapp", Some(b"lgit")));
    }
}
