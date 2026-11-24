//! Directory enumeration entries returned by QUERY_DIRECTORY ([MS-FSCC]
//! §2.4.8, §2.4.14, §2.4.17, §2.4.18, §2.4.19, §2.4.20, §2.4.33).
//!
//! All supported classes are decoded into one [`DirEntry`] so a client can
//! switch classes without changing its listing code. Names stay in their
//! UTF-16 wire form ([`Utf16Name`], a zero-copy slice of the response).
//! Iteration over the `NextEntryOffset` chain is bounds-checked and always
//! makes forward progress, so hostile input can neither panic nor loop.

use bytes::{BufMut, Bytes, BytesMut};

use super::{FileAttributes, FileInfoClass, FileTime};
use crate::error::{ProtoError, Result};
use crate::wire::{Reader, Utf16Name, len_u32, padding, patch_u32};

/// One directory entry.
///
/// Fields that a class does not carry are zero / `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirEntry {
    /// `FileIndex` (position hint; usually 0 on NTFS).
    pub file_index: u32,
    /// Creation time.
    pub creation_time: FileTime,
    /// Last access time.
    pub last_access_time: FileTime,
    /// Last write time.
    pub last_write_time: FileTime,
    /// Change time.
    pub change_time: FileTime,
    /// File size.
    pub end_of_file: u64,
    /// Allocated size.
    pub allocation_size: u64,
    /// Attributes.
    pub file_attributes: FileAttributes,
    /// `EaSize` (holds the reparse tag for reparse points in the classes
    /// without a dedicated tag field; see [`DirEntry::reparse_tag`]).
    pub ea_size: u32,
    /// 8.3 short name (Both classes).
    pub short_name: Option<Utf16Name>,
    /// 64-bit file id (IdBoth/IdFull classes).
    pub file_id: Option<u64>,
    /// 128-bit file id (IdExtd class).
    pub file_id_128: Option<[u8; 16]>,
    /// Dedicated reparse tag field (IdExtd class).
    pub reparse_point_tag: Option<u32>,
    /// The entry name.
    pub file_name: Utf16Name,
}

impl DirEntry {
    /// `true` if the entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.file_attributes.contains(FileAttributes::DIRECTORY)
    }

    /// `true` for the `.` and `..` pseudo entries.
    pub fn is_dot_or_dot_dot(&self) -> bool {
        self.file_name.is_dot() || self.file_name.is_dot_dot()
    }

    /// The reparse tag if the entry is a reparse point: the dedicated field
    /// when present, otherwise `EaSize` ([MS-FSCC]: "If
    /// FILE_ATTRIBUTE_REPARSE_POINT is set, EaSize contains the reparse tag").
    pub fn reparse_tag(&self) -> Option<u32> {
        if !self.file_attributes.contains(FileAttributes::REPARSE_POINT) {
            return None;
        }
        Some(self.reparse_point_tag.unwrap_or(self.ea_size))
    }
}

/// Layout description of a directory class.
#[derive(Clone, Copy)]
struct Layout {
    /// Size of the fixed part (before the name).
    fixed: usize,
    /// `true` if the class has the 64-byte common prefix of times/sizes.
    full: bool,
}

fn layout(class: FileInfoClass) -> Option<Layout> {
    Some(match class {
        FileInfoClass::DIRECTORY => Layout { fixed: 64, full: true },
        FileInfoClass::FULL_DIRECTORY => Layout { fixed: 68, full: true },
        FileInfoClass::BOTH_DIRECTORY => Layout { fixed: 94, full: true },
        FileInfoClass::ID_BOTH_DIRECTORY => Layout { fixed: 104, full: true },
        FileInfoClass::ID_FULL_DIRECTORY => Layout { fixed: 80, full: true },
        FileInfoClass::ID_EXTD_DIRECTORY => Layout { fixed: 88, full: true },
        FileInfoClass::NAMES => Layout { fixed: 12, full: false },
        _ => return None,
    })
}

/// `true` if `class` can be decoded by [`DirectoryEntries`].
pub fn is_directory_class(class: FileInfoClass) -> bool {
    layout(class).is_some()
}

/// Iterator over the entries of a QUERY_DIRECTORY output buffer.
#[derive(Debug, Clone)]
pub struct DirectoryEntries {
    class: FileInfoClass,
    fixed: usize,
    full: bool,
    buf: Bytes,
    /// Offset of the next entry; `None` once finished or after an error.
    pos: Option<usize>,
    /// Error to report after the last good entry.
    pending_error: Option<ProtoError>,
}

impl DirectoryEntries {
    /// Iterate the entries of `buf` (the zero-copy output buffer of a
    /// QUERY_DIRECTORY response) for `class`.
    pub fn new(class: FileInfoClass, buf: Bytes) -> Result<Self> {
        let l = layout(class).ok_or(ProtoError::Unsupported("directory information class"))?;
        let pos = (!buf.is_empty()).then_some(0);
        Ok(DirectoryEntries { class, fixed: l.fixed, full: l.full, buf, pos, pending_error: None })
    }

    /// The information class being decoded.
    pub fn class(&self) -> FileInfoClass {
        self.class
    }

    fn entry_at(&self, pos: usize) -> Result<(DirEntry, usize)> {
        const W: &str = "directory entry";
        let rest = &self.buf[pos..];
        let mut r = Reader::new(rest, W);
        if rest.len() < self.fixed {
            return Err(ProtoError::Truncated { what: W, need: pos + self.fixed, have: self.buf.len() });
        }
        let next = r.u32()? as usize;
        let mut e = DirEntry { file_index: r.u32()?, ..Default::default() };
        let name_len;
        if self.full {
            e.creation_time = FileTime(r.u64()?);
            e.last_access_time = FileTime(r.u64()?);
            e.last_write_time = FileTime(r.u64()?);
            e.change_time = FileTime(r.u64()?);
            e.end_of_file = r.u64()?;
            e.allocation_size = r.u64()?;
            e.file_attributes = FileAttributes::from_bits_retain(r.u32()?);
            name_len = r.u32()? as usize;
            match self.class {
                FileInfoClass::DIRECTORY => {}
                FileInfoClass::FULL_DIRECTORY => e.ea_size = r.u32()?,
                FileInfoClass::BOTH_DIRECTORY | FileInfoClass::ID_BOTH_DIRECTORY => {
                    e.ea_size = r.u32()?;
                    let short_len = usize::from(r.u8()?).min(24);
                    r.skip(1)?;
                    let short_start = pos + r.pos();
                    r.skip(24)?;
                    e.short_name =
                        Some(Utf16Name::from_wire(self.buf.slice(short_start..short_start + short_len)));
                    if self.class == FileInfoClass::ID_BOTH_DIRECTORY {
                        r.skip(2)?;
                        e.file_id = Some(r.u64()?);
                    }
                }
                FileInfoClass::ID_FULL_DIRECTORY => {
                    e.ea_size = r.u32()?;
                    r.skip(4)?;
                    e.file_id = Some(r.u64()?);
                }
                FileInfoClass::ID_EXTD_DIRECTORY => {
                    e.ea_size = r.u32()?;
                    e.reparse_point_tag = Some(r.u32()?);
                    e.file_id_128 = Some(r.array()?);
                }
                _ => unreachable!("layout() only admits known classes"),
            }
        } else {
            name_len = r.u32()? as usize;
        }
        debug_assert_eq!(r.pos(), self.fixed);
        let name_start = pos + self.fixed;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&end| end <= self.buf.len())
            .ok_or(ProtoError::Truncated { what: W, need: name_start.saturating_add(name_len), have: self.buf.len() })?;
        e.file_name = Utf16Name::from_wire(self.buf.slice(name_start..name_end));
        Ok((e, next))
    }
}

impl Iterator for DirectoryEntries {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(e) = self.pending_error.take() {
            return Some(Err(e));
        }
        let pos = self.pos.take()?;
        match self.entry_at(pos) {
            Ok((entry, next)) => {
                if next != 0 {
                    // The next entry must start past this entry's fixed part
                    // and inside the buffer; anything else is malformed. The
                    // current entry is still yielded, the error comes next.
                    match pos.checked_add(next) {
                        Some(n) if next >= self.fixed && n < self.buf.len() => self.pos = Some(n),
                        _ => {
                            self.pending_error =
                                Some(ProtoError::malformed("directory entry", "NextEntryOffset out of range"))
                        }
                    }
                }
                Some(Ok(entry))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Encode `entries` as a QUERY_DIRECTORY output buffer of `class`
/// (entries 8-byte aligned). Used by mock servers and tests.
pub fn encode_directory_entries(class: FileInfoClass, entries: &[DirEntry], dst: &mut BytesMut) -> Result<()> {
    let l = layout(class).ok_or(ProtoError::Unsupported("directory information class"))?;
    let base = dst.len();
    for (i, e) in entries.iter().enumerate() {
        let start = dst.len();
        dst.put_u32_le(0);
        dst.put_u32_le(e.file_index);
        let name_len = len_u32(e.file_name.len(), "file name too long")?;
        if l.full {
            for t in [e.creation_time, e.last_access_time, e.last_write_time, e.change_time] {
                dst.put_u64_le(t.0);
            }
            dst.put_u64_le(e.end_of_file);
            dst.put_u64_le(e.allocation_size);
            dst.put_u32_le(e.file_attributes.bits());
            dst.put_u32_le(name_len);
            match class {
                FileInfoClass::DIRECTORY => {}
                FileInfoClass::FULL_DIRECTORY => dst.put_u32_le(e.ea_size),
                FileInfoClass::BOTH_DIRECTORY | FileInfoClass::ID_BOTH_DIRECTORY => {
                    dst.put_u32_le(e.ea_size);
                    let short = e.short_name.as_ref().map(|s| &s.as_bytes()[..s.len().min(24)]).unwrap_or(&[]);
                    dst.put_u8(short.len() as u8);
                    dst.put_u8(0);
                    dst.put_slice(short);
                    dst.put_bytes(0, 24 - short.len());
                    if class == FileInfoClass::ID_BOTH_DIRECTORY {
                        dst.put_u16_le(0);
                        dst.put_u64_le(e.file_id.unwrap_or(0));
                    }
                }
                FileInfoClass::ID_FULL_DIRECTORY => {
                    dst.put_u32_le(e.ea_size);
                    dst.put_u32_le(0);
                    dst.put_u64_le(e.file_id.unwrap_or(0));
                }
                FileInfoClass::ID_EXTD_DIRECTORY => {
                    dst.put_u32_le(e.ea_size);
                    dst.put_u32_le(e.reparse_point_tag.unwrap_or(0));
                    dst.put_slice(&e.file_id_128.unwrap_or([0; 16]));
                }
                _ => unreachable!(),
            }
        } else {
            dst.put_u32_le(name_len);
        }
        dst.put_slice(e.file_name.as_bytes());
        if i + 1 < entries.len() {
            dst.put_bytes(0, padding(dst.len() - base, 8));
            let next = (dst.len() - start) as u32;
            patch_u32(dst, start, next);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(class: FileInfoClass) -> Vec<DirEntry> {
        let mut a = DirEntry {
            file_index: 0,
            creation_time: FileTime(1),
            last_access_time: FileTime(2),
            last_write_time: FileTime(3),
            change_time: FileTime(4),
            end_of_file: 5,
            allocation_size: 4096,
            file_attributes: FileAttributes::ARCHIVE,
            file_name: Utf16Name::from("file.txt"),
            ..Default::default()
        };
        let mut b = DirEntry {
            file_attributes: FileAttributes::DIRECTORY,
            file_name: Utf16Name::from("sub"),
            ..a.clone()
        };
        match class {
            FileInfoClass::FULL_DIRECTORY => a.ea_size = 7,
            FileInfoClass::BOTH_DIRECTORY | FileInfoClass::ID_BOTH_DIRECTORY => {
                a.short_name = Some(Utf16Name::from("FILE~1.TXT"));
                b.short_name = Some(Utf16Name::default());
                if class == FileInfoClass::ID_BOTH_DIRECTORY {
                    a.file_id = Some(42);
                    b.file_id = Some(43);
                }
            }
            FileInfoClass::ID_FULL_DIRECTORY => {
                a.file_id = Some(1);
                b.file_id = Some(2);
            }
            FileInfoClass::ID_EXTD_DIRECTORY => {
                a.file_id_128 = Some([1; 16]);
                a.reparse_point_tag = Some(0);
                b.file_id_128 = Some([2; 16]);
                b.reparse_point_tag = Some(0xA000_000C);
                b.file_attributes |= FileAttributes::REPARSE_POINT;
            }
            FileInfoClass::NAMES => {
                for e in [&mut a, &mut b] {
                    *e = DirEntry { file_name: e.file_name.clone(), ..Default::default() };
                }
            }
            _ => {}
        }
        vec![a, b]
    }

    #[test]
    fn round_trip_all_classes() {
        for class in [
            FileInfoClass::DIRECTORY,
            FileInfoClass::FULL_DIRECTORY,
            FileInfoClass::BOTH_DIRECTORY,
            FileInfoClass::ID_BOTH_DIRECTORY,
            FileInfoClass::ID_FULL_DIRECTORY,
            FileInfoClass::ID_EXTD_DIRECTORY,
            FileInfoClass::NAMES,
        ] {
            let entries = sample(class);
            let mut b = BytesMut::new();
            encode_directory_entries(class, &entries, &mut b).unwrap();
            let got: Vec<_> = DirectoryEntries::new(class, b.clone().freeze())
                .unwrap()
                .collect::<Result<_>>()
                .unwrap();
            assert_eq!(got, entries, "{class:?}");
            // Every truncation either errors or yields a prefix; never panics.
            for i in 0..b.len() {
                for r in DirectoryEntries::new(class, b.clone().freeze().slice(..i)).unwrap() {
                    let _ = r;
                }
            }
        }
    }

    #[test]
    fn reparse_tag_from_ea_size() {
        let e = DirEntry {
            file_attributes: FileAttributes::REPARSE_POINT,
            ea_size: 0xA000_000C,
            ..Default::default()
        };
        assert_eq!(e.reparse_tag(), Some(0xA000_000C));
        assert_eq!(DirEntry::default().reparse_tag(), None);
    }

    #[test]
    fn bad_next_offset_reports_error() {
        let mut b = BytesMut::new();
        encode_directory_entries(FileInfoClass::DIRECTORY, &sample(FileInfoClass::DIRECTORY), &mut b).unwrap();
        // Point the first entry's NextEntryOffset at itself (+1).
        patch_u32(&mut b, 0, 1);
        let items: Vec<_> = DirectoryEntries::new(FileInfoClass::DIRECTORY, b.freeze()).unwrap().collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }

    #[test]
    fn unsupported_class() {
        assert!(DirectoryEntries::new(FileInfoClass::BASIC, Bytes::new()).is_err());
        assert_eq!(DirectoryEntries::new(FileInfoClass::DIRECTORY, Bytes::new()).unwrap().count(), 0);
    }
}
