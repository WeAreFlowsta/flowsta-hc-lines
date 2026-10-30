//! A line-free view of a record, and the decoders that produce it.
//!
//! A `Record` from one line does not decode with the other line's types
//! (the 0.7 action model changed the wire shape). What crosses unchanged:
//! an app's own entry structs (msgpack, the same bytes on both lines) and
//! hashes (39 raw bytes, serialized identically by both lines' types).

use crate::{Error, Line, Result};

/// What an app needs from a record, whichever line produced it. Apps keep
/// these on disk (msgpack with named fields), so the shape is a format:
/// fields are only ever added, as optional.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecordView {
    /// The action hash, 39 raw bytes.
    #[serde(with = "serde_bytes")]
    pub action_hash: Vec<u8>,
    /// The author's agent key, 39 raw bytes.
    #[serde(with = "serde_bytes")]
    pub author: Vec<u8>,
    /// Action timestamp, microseconds since the epoch.
    pub timestamp_us: i64,
    /// The app entry's msgpack bytes, when the record carries an entry.
    #[serde(default, with = "serde_bytes_opt")]
    pub entry: Option<Vec<u8>>,
    /// The signed action as that line encodes it (msgpack): the proof a
    /// carried record travels with.
    #[serde(with = "serde_bytes")]
    pub signed_action: Vec<u8>,
    pub line: Line,
}

/// `serde_bytes` for an `Option<Vec<u8>>`.
mod serde_bytes_opt {
    pub fn serialize<S: serde::Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&serde_bytes::Bytes::new(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let v: Option<serde_bytes::ByteBuf> = serde::Deserialize::deserialize(d)?;
        Ok(v.map(|b| b.into_vec()))
    }
}

impl RecordView {
    /// Decode the entry as one of the app's own entry structs.
    pub fn entry_as<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let bytes = self.entry.as_ref().ok_or_else(|| decode(self.line, "Record has no entry".into()))?;
        rmp_serde::from_slice(bytes).map_err(|e| decode(self.line, format!("Failed to decode entry: {}", e)))
    }
}

fn decode(line: Line, what: String) -> Error {
    Error::Decode { line: Some(line), what }
}

#[allow(dead_code)]
fn not_compiled(line: Line) -> Error {
    decode(line, format!("The {} line is not compiled into this build", line))
}

/// Decode a zome output of `Vec<Record>` from the given line.
pub fn records(line: Line, bytes: &[u8]) -> Result<Vec<RecordView>> {
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => {
            let recs: Vec<crate::v06::holochain_types::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| decode(line, format!("Failed to decode records (0.6): {}", e)))?;
            recs.iter().map(view_06).collect()
        }
        #[cfg(feature = "line-07")]
        Line::V07 => {
            let recs: Vec<crate::v07::holochain_types::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| decode(line, format!("Failed to decode records (0.7): {}", e)))?;
            recs.iter().map(view_07).collect()
        }
        #[allow(unreachable_patterns)]
        other => Err(not_compiled(other)),
    }
}

/// Decode a zome output of `Option<Record>` from the given line.
pub fn record_opt(line: Line, bytes: &[u8]) -> Result<Option<RecordView>> {
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => {
            let rec: Option<crate::v06::holochain_types::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| decode(line, format!("Failed to decode record (0.6): {}", e)))?;
            rec.as_ref().map(view_06).transpose()
        }
        #[cfg(feature = "line-07")]
        Line::V07 => {
            let rec: Option<crate::v07::holochain_types::prelude::Record> =
                rmp_serde::from_slice(bytes).map_err(|e| decode(line, format!("Failed to decode record (0.7): {}", e)))?;
            rec.as_ref().map(view_07).transpose()
        }
        #[allow(unreachable_patterns)]
        other => Err(not_compiled(other)),
    }
}

/// Decode a zome output of one `Record` from the given line.
pub fn record(line: Line, bytes: &[u8]) -> Result<RecordView> {
    match line {
        #[cfg(feature = "line-06")]
        Line::V06 => {
            let rec: crate::v06::holochain_types::prelude::Record =
                rmp_serde::from_slice(bytes).map_err(|e| decode(line, format!("Failed to decode record (0.6): {}", e)))?;
            view_06(&rec)
        }
        #[cfg(feature = "line-07")]
        Line::V07 => {
            let rec: crate::v07::holochain_types::prelude::Record =
                rmp_serde::from_slice(bytes).map_err(|e| decode(line, format!("Failed to decode record (0.7): {}", e)))?;
            view_07(&rec)
        }
        #[allow(unreachable_patterns)]
        other => Err(not_compiled(other)),
    }
}

/// The view of a 0.6 record. Fails only if its signed action does not
/// encode (it used to become empty bytes silently).
#[cfg(feature = "line-06")]
pub fn view_06(r: &crate::v06::holochain_types::prelude::Record) -> Result<RecordView> {
    Ok(RecordView {
        action_hash: r.action_address().get_raw_39().to_vec(),
        author: r.action().author().get_raw_39().to_vec(),
        timestamp_us: r.action().timestamp().as_micros(),
        entry: r.entry().as_option().and_then(|e| e.as_app_entry()).map(|a| a.as_ref().bytes().to_vec()),
        signed_action: rmp_serde::to_vec_named(r.signed_action())
            .map_err(|e| decode(Line::V06, format!("Failed to encode the signed action (0.6): {}", e)))?,
        line: Line::V06,
    })
}

/// The view of a 0.7 record. Fails only if its signed action does not
/// encode (it used to become empty bytes silently).
#[cfg(feature = "line-07")]
pub fn view_07(r: &crate::v07::holochain_types::prelude::Record) -> Result<RecordView> {
    Ok(RecordView {
        action_hash: r.action_address().get_raw_39().to_vec(),
        author: r.action().author().get_raw_39().to_vec(),
        timestamp_us: r.action().timestamp().as_micros(),
        entry: r.entry().as_option().and_then(|e| e.as_app_entry()).map(|a| a.as_ref().bytes().to_vec()),
        signed_action: rmp_serde::to_vec_named(r.signed_action())
            .map_err(|e| decode(Line::V07, format!("Failed to encode the signed action (0.7): {}", e)))?,
        line: Line::V07,
    })
}

#[cfg(all(test, feature = "line-06", feature = "line-07"))]
mod tests {
    use super::*;

    fn sample() -> RecordView {
        RecordView {
            action_hash: vec![0x84, 0x29, 0x24, 7, 7, 7],
            author: vec![0x84, 0x20, 0x24, 9, 9],
            timestamp_us: 1_761_800_000_000_000,
            entry: Some(vec![0x81, 0xa1, 0x61, 0x01]),
            signed_action: vec![0x92, 0xc0, 0xc0],
            line: Line::V07,
        }
    }

    /// Apps keep record views on disk (msgpack, named fields): the bytes are
    /// a format. A change here breaks every file already written.
    #[test]
    fn the_on_disk_bytes_never_change() {
        let golden = "86ab616374696f6e5f68617368c406842924070707a6617574686f72c4058420240909ac74696d657374616d705f7573cf00064259072a5000a5656e747279c40481a16101ad7369676e65645f616374696f6ec40392c0c0a46c696e65a3563037";
        let hex = |b: Vec<u8>| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(hex(rmp_serde::to_vec_named(&sample()).unwrap()), golden);
        let none = RecordView { entry: None, line: Line::V06, ..sample() };
        let bytes = rmp_serde::to_vec_named(&none).unwrap();
        assert_eq!(rmp_serde::from_slice::<RecordView>(&bytes).unwrap(), none);
        // A file written before `entry` existed still reads.
        #[derive(serde::Serialize)]
        struct Older<'a> {
            #[serde(with = "serde_bytes")]
            action_hash: &'a [u8],
            #[serde(with = "serde_bytes")]
            author: &'a [u8],
            timestamp_us: i64,
            #[serde(with = "serde_bytes")]
            signed_action: &'a [u8],
            line: Line,
        }
        let s = sample();
        let older = rmp_serde::to_vec_named(&Older { action_hash: &s.action_hash, author: &s.author, timestamp_us: s.timestamp_us, signed_action: &s.signed_action, line: s.line }).unwrap();
        assert_eq!(rmp_serde::from_slice::<RecordView>(&older).unwrap().entry, None);
    }

    #[test]
    fn hashes_are_the_same_bytes_on_both_lines() {
        use crate::{v06::holochain_types as t06, v07::holochain_types as t07};
        let h = t06::prelude::ActionHash::from_raw_32(vec![7u8; 32]);
        let h7 = t07::prelude::ActionHash::from_raw_39(h.get_raw_39().to_vec());
        assert_eq!(h.to_string(), h7.to_string());
        assert_eq!(rmp_serde::to_vec_named(&h).unwrap(), rmp_serde::to_vec_named(&h7).unwrap());
        let k = t06::prelude::AgentPubKey::from_raw_32(vec![9u8; 32]);
        let k7 = t07::prelude::AgentPubKey::from_raw_39(k.get_raw_39().to_vec());
        assert_eq!(rmp_serde::to_vec_named(&k).unwrap(), rmp_serde::to_vec_named(&k7).unwrap());
    }

    #[test]
    fn app_structs_encode_identically_for_both_lines() {
        use crate::{v06::holochain_types as t06, v07::holochain_types as t07};
        #[derive(serde::Serialize, Debug)]
        struct In {
            title: String,
            n: u32,
        }
        let a = t06::prelude::ExternIO::encode(&In { title: "x".into(), n: 2 }).unwrap().into_vec();
        let b = t07::prelude::ExternIO::encode(&In { title: "x".into(), n: 2 }).unwrap().into_vec();
        assert_eq!(a, b);
        assert_eq!(a, rmp_serde::to_vec_named(&In { title: "x".into(), n: 2 }).unwrap());
    }

    #[test]
    fn errors_read_as_the_old_strings() {
        let e = records(Line::V06, &[0xc1]).unwrap_err();
        assert!(e.to_string().starts_with("Failed to decode records (0.6): "), "{e}");
        let e = RecordView { entry: None, ..sample() }.entry_as::<u8>().unwrap_err();
        assert_eq!(e.to_string(), "Record has no entry");
    }
}
