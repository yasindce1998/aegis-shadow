use common::EventHeader;
use offense::{classify_event, EventClassification};

pub const TEST_PID: u32 = 1337;
pub const TEST_PID_2: u32 = 2600;
pub const TEST_PID_3: u32 = 3100;
pub const TEST_TIMESTAMP: u64 = 1_000_000_000;

pub fn make_event(event_type: u32, pid: u32, context: u64) -> EventHeader {
    EventHeader {
        event_type,
        pid,
        timestamp_ns: TEST_TIMESTAMP,
        context,
    }
}

pub fn make_event_at(event_type: u32, pid: u32, context: u64, timestamp_ns: u64) -> EventHeader {
    EventHeader {
        event_type,
        pid,
        timestamp_ns,
        context,
    }
}

pub fn assert_classifies_to(event_type: u32, expected_variant: &str) {
    let event = make_event(event_type, TEST_PID, 42);
    let classification = classify_event(&event);
    let debug_str = format!("{:?}", classification);
    assert!(
        debug_str.starts_with(expected_variant),
        "event_type {} classified as {:?}, expected to start with '{}'",
        event_type,
        classification,
        expected_variant
    );
}

pub fn classify_with(event_type: u32, pid: u32, context: u64) -> EventClassification {
    let event = make_event(event_type, pid, context);
    classify_event(&event)
}
