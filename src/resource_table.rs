use crate::{
    abi::{RSC_CARVEOUT, RSC_VDEV, RSC_TRACE, RSC_DEVMEM}, endian::EndianParse, file::Class, parse::{ParseAt, ReadBytesExt}, ParseError
};

/// Firmware resource table header
/// The offsets and entries are left as raw bytes due to the dynamic nature of the possible
/// variants and lengths, this means each entry needs to be parsed when iterating
/// The entire table is parsed when constructed with `parse_at` so that parsing errors are not
/// encountered during iterating, which has no error state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceTable<'data, E: EndianParse> {
    /// Version number
    pub version: u32,
    /// Number of resource entries
    pub num_resources: u32,
    /// Array of offsets pointing at the various resource entries
    /// These offsets are from the start of the section, so you must subtract
    /// (size_of::<u32>() * 4) + resource_offsets.len() to index into the resource_entries
    /// These are u32s in the endian of the elf, so they must be parsed as they are needed
    pub resource_offsets: &'data [u8],
    /// The rest of the section, to be parsed into FirmwareResource as needed
    pub resource_entries: &'data [u8],

    /// Used to create the iterator later
    endian: E,
    /// Used to create the iterator later
    class: Class,
}

impl<'data, E: EndianParse> ResourceTable<'data, E> {
    pub fn parse_at(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        let version = endian.parse_u32_at(offset, data)?;
        let num_resources = endian.parse_u32_at(offset, data)?;

        let _reserved = endian.parse_u32_at(offset, data)?;
        let _reserved = endian.parse_u32_at(offset, data)?;

        let resource_offsets = {
            let resource_offsets_start = *offset;
            let resource_offsets_end =
                resource_offsets_start + (size_of::<u32>() * num_resources as usize);
            *offset = resource_offsets_end;
            &data.get_bytes(resource_offsets_start..resource_offsets_end)?
        };

        let resource_entries = {
            let resource_entries_start = *offset;
            let resource_entries_end = data.len();
            *offset = resource_entries_end;
            &data.get_bytes(resource_entries_start..resource_entries_end)?
        };
        // Parse all resource entries
        // The itererator cannot return an error state so the checks are done here
        let resource_table = ResourceTable {
            version,
            num_resources,
            resource_offsets,
            resource_entries,
            endian,
            class,
        };
        for i in 0..num_resources {
            let _ = resource_table.get(i as usize)?;
        }
        Ok(resource_table)
    }
    fn get(
        &self,
        entry: usize,
    ) -> Result<FirmwareResource<'data, E>, ParseError> {
        if entry >= self.num_resources as usize {
            return Err(ParseError::BadOffset(entry as u64));
        }

        // offset into the resource_entries
        let mut resource_offsets_offset: usize = entry * size_of::<u32>();

        // offset into the resource_entries
        let mut resource_entry_offset = self.endian
            .parse_u32_at(&mut resource_offsets_offset, self.resource_offsets)? as usize;
        // Subtract the header size
        resource_entry_offset = resource_entry_offset
            - ((size_of::<u32>() * 4) + self.resource_offsets.len()) as usize;

        FirmwareResource::parse_at(
            self.endian,
            self.class,
            &mut resource_entry_offset,
            self.resource_entries,
        )
    }
    pub fn to_iter(
        &'data self,
    ) -> FirmwareResourceIterator<'data, E> {
        FirmwareResourceIterator {
            idx: 0,
            resource_table: self,
        }
    }
}

impl<'data, E: EndianParse> IntoIterator for &'data ResourceTable<'data, E> {
    type Item = FirmwareResource<'data, E>;
    type IntoIter = FirmwareResourceIterator<'data, E>;
    fn into_iter(self) -> Self::IntoIter {
        self.to_iter()
    }
}

impl<'data, E: EndianParse> Iterator for FirmwareResourceIterator<'data, E> {
    type Item = FirmwareResource<'data, E>;
    fn next(&mut self) -> Option<Self::Item> {
        let out = self.resource_table.get(self.idx).ok();
        self.idx += 1;
        out
    }
}

#[derive(Debug)]
pub struct FirmwareResourceIterator<'data, E: EndianParse> {
    idx: usize,
    resource_table: &'data ResourceTable<'data, E>,
}

/// This enum contains parsed firmware resource variants that can be matched on
#[derive(Debug, PartialEq, Eq)]
pub enum FirmwareResource<'data, E: EndianParse> {
    Carveout(FirmwareResourceCarveout<'data>),
    Devmem(FirmwareResourceDevmem<'data>),
    Trace(FirmwareResourceTrace<'data>),
    Vdev(FirmwareResourceVdev<'data, E>),
    /// Represents Resource with an unsupported type
    /// These are usually vendor defined resources
    Unknown(u32),
}

pub const FW_RSC_ADDR_ANY: u32 = u32::MAX;

impl<'data, E: EndianParse> FirmwareResource<'data, E> {
    fn parse_at(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        // Can break this out to enum if needed
        let resource_type = endian.parse_u32_at(offset, data)?;
        match resource_type {
            RSC_CARVEOUT => Ok(FirmwareResource::Carveout(
                FirmwareResourceCarveout::parse_at(
                    endian,
                    class,
                    offset,
                    &data[..*offset + FirmwareResourceCarveout::size_for(class)],
                )?,
            )),
            RSC_DEVMEM => Ok(FirmwareResource::Devmem(
                FirmwareResourceDevmem::parse_at(
                    endian,
                    class,
                    offset,
                    &data[..*offset + FirmwareResourceDevmem::size_for(class)],
                )?
            )),
            RSC_TRACE => Ok(FirmwareResource::Trace(
                FirmwareResourceTrace::parse_at(
                    endian,
                    class,
                    offset,
                    &data[..*offset + FirmwareResourceTrace::size_for(class)],
                )?
            )),
            RSC_VDEV => Ok(FirmwareResource::Vdev(
                FirmwareResourceVdev::parse_at(
                    endian,
                    class,
                    offset,
                    &data,
                )?
            )),
            _ => Ok(FirmwareResource::Unknown(resource_type)),
        }
    }
}

/// physically contiguous memory request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareResourceCarveout<'data> {
    /// Device address
    pub da: u32,
    /// Physical address
    pub pa: u32,
    /// Length in bytes
    pub len: u32,
    /// iommu protection flags
    pub flags: u32,
    /// Human-readable name of the requested memory region
    pub name: &'data [u8; 32],
}
impl<'data> FirmwareResourceCarveout<'data> {
    fn size_for(_class: Class) -> usize {
        (size_of::<u32>() * 5) + 32
    }
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        let da = endian.parse_u32_at(offset, data)?;
        let pa = endian.parse_u32_at(offset, data)?;
        let len = endian.parse_u32_at(offset, data)?;
        let flags = endian.parse_u32_at(offset, data)?;
        let _reserved = endian.parse_u32_at(offset, data)?;
        let name_start = *offset;
        let name_end = name_start + 32;
        let name = data.get_bytes(name_start..name_end)?.try_into()?;
        *offset = name_end;

        Ok(FirmwareResourceCarveout {
            da,
            pa,
            len,
            flags,
            name,
        })
    }
}

/// iommu mapping request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareResourceDevmem<'data> {
    /// Device address
    pub da: u32,
    /// Physical address
    pub pa: u32,
    /// Length in bytes
    pub len: u32,
    /// iommu protection flags
    pub flags: u32,
    /// Human-readable name of the requested memory region
    pub name: &'data [u8; 32],
}

impl<'data> FirmwareResourceDevmem<'data> {
    fn size_for(_class: Class) -> usize {
        (size_of::<u32>() * 5) + 32
    }
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        let da = endian.parse_u32_at(offset, data)?;
        let pa = endian.parse_u32_at(offset, data)?;
        let len = endian.parse_u32_at(offset, data)?;
        let flags = endian.parse_u32_at(offset, data)?;
        let _reserved = endian.parse_u32_at(offset, data)?;
        let name_start = *offset;
        let name_end = name_start + 32;
        let name = data.get_bytes(name_start..name_end)?.try_into()?;
        *offset = name_end;

        Ok(FirmwareResourceDevmem {
            da,
            pa,
            len,
            flags,
            name,
        })
    }
}


/// trace buffer declaration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareResourceTrace<'data> {
    /// Device address
    pub da: u32,
    /// Length in bytes
    pub len: u32,
    /// Human-readable name of the requested memory region
    pub name: &'data [u8; 32],
}

impl<'data> FirmwareResourceTrace<'data> {
    fn size_for(_class: Class) -> usize {
        (size_of::<u32>() * 3) + 32
    }
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        let da = endian.parse_u32_at(offset, data)?;
        let len = endian.parse_u32_at(offset, data)?;
        let _reserved = endian.parse_u32_at(offset, data)?;
        let name_start = *offset;
        let name_end = name_start + 32;
        let name = data.get_bytes(name_start..name_end)?.try_into()?;
        *offset = name_end;

        Ok(FirmwareResourceTrace { da, len, name })
    }
}

/// vring descriptor entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareResourceVdevVring {
    /// Device address
    pub da: u32,
    /// The alignment between the consumer and producer parts of the vring
    pub align: u32,
    /// Number of buffers supported by this vring (must be power of two)
    pub num: u32,
    /// A unique rproc-wide notify index for this vring. This notify
    /// index is used when kicking a remote processor, to let it know that this
    /// vring is triggered
    pub notify_id: u32,
    /// physical address
    pub pa: u32,
}

impl ParseAt for FirmwareResourceVdevVring {
    fn size_for(_class: Class) -> usize {
        size_of::<u32>() * 5
    }
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let da = endian.parse_u32_at(offset, data)?;
        let align = endian.parse_u32_at(offset, data)?;
        let num = endian.parse_u32_at(offset, data)?;
        let notify_id = endian.parse_u32_at(offset, data)?;
        let pa = endian.parse_u32_at(offset, data)?;

        Ok(FirmwareResourceVdevVring {
            da,
            align,
            num,
            notify_id,
            pa,
        })
    }
}

impl<'data, E: EndianParse> IntoIterator for &'data FirmwareResourceVdev<'data, E> {
    type Item = FirmwareResourceVdevVring;
    type IntoIter = FirmwareResourceVdevVringIterator<'data, E>;
    fn into_iter(self) -> Self::IntoIter {
        self.to_iter()
    }
}

impl<'data, E: EndianParse> Iterator for FirmwareResourceVdevVringIterator<'data, E> {
    type Item = FirmwareResourceVdevVring;
    fn next(&mut self) -> Option<Self::Item> {
        let out = self.firmware_resource_vdev.get(self.idx).ok();
        self.idx += 1;
        out
    }
}

#[derive(Debug)]
pub struct FirmwareResourceVdevVringIterator<'data, E: EndianParse> {
    idx: usize,
    firmware_resource_vdev: &'data FirmwareResourceVdev<'data, E>,
}

/// virtio device header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareResourceVdev<'data, E: EndianParse> {
    /// virtio device id (as in virtio_ids.h)
    pub id: u32,
    /// A unique rproc-wide notify index for this vdev. This notify
    /// index is used when kicking a remote processor, to let it know that the
    /// status/features of this vdev have changes.
    pub notify_id: u32,
    /// Specifies the virtio device features supported by the firmware
    pub dfeatures: u32,
    /// A place holder used by the host to write back the
    /// negotiated features that are supported by both sides.
    pub gfeatures: u32,
    /// A place holder where the host will indicate its virtio progress.
    pub status: u8, 
    /// Indicates how many vrings are described in this vdev header
    pub num_of_vrings: u8,
    /// An array of num_of_vrings entries
    pub vrings: &'data [u8],

    /// Used to create the iterator later
    endian: E,
    /// Used to create the iterator later
    class: Class,
}

impl<'data, E: EndianParse> FirmwareResourceVdev<'data, E> {
    fn parse_at(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        let id = endian.parse_u32_at(offset, data)?;
        let notify_id = endian.parse_u32_at(offset, data)?;
        let dfeatures = endian.parse_u32_at(offset, data)?;
        let gfeatures = endian.parse_u32_at(offset, data)?;
        let config_len = endian.parse_u32_at(offset, data)?;
        let status = endian.parse_u8_at(offset, data)?;
        let num_of_vrings = endian.parse_u8_at(offset, data)?;
        let _reserved = endian.parse_u8_at(offset, data)?;
        let _reserved = endian.parse_u8_at(offset, data)?;
        let vrings = data.get_bytes(*offset..*offset + (num_of_vrings as usize * FirmwareResourceVdevVring::size_for(class))  as usize)?;
        *offset = *offset + config_len as usize;
        Ok(FirmwareResourceVdev {
            id,
            notify_id,
            dfeatures,
            gfeatures,
            num_of_vrings,
            status,
            vrings,
            endian,
            class,
        })
    }
    pub fn to_iter(
        &'data self,
    ) -> FirmwareResourceVdevVringIterator<'data, E> {
        FirmwareResourceVdevVringIterator {
            idx: 0,
            firmware_resource_vdev: self,
        }
    }
    fn get(
        &self,
        entry: usize,
    ) -> Result<FirmwareResourceVdevVring, ParseError> {
        if entry >= self.num_of_vrings as usize {
            return Err(ParseError::BadOffset(entry as u64));
        }

        let mut offset = 0;
        FirmwareResourceVdevVring::parse_at(
            self.endian,
            self.class,
            &mut offset,
            &self.vrings[entry * FirmwareResourceVdevVring::size_for(self.class)..(entry + 1) * FirmwareResourceVdevVring::size_for(self.class)],
        )
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};

    #[test]
    fn parse_resource_table_hdr() {
        #[rustfmt::skip]
        let data = [
            0x00, 0x00, 0x00, 0x01, // version
            0x00, 0x00, 0x00, 0x00, // num_resources
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
        ];
        let mut offset = 0;

        let resource_table = ResourceTable::parse_at(BigEndian, Class::ELF32, &mut offset, &data)
            .expect("Failed to parse");

        assert_eq!(resource_table.version, 1);
        assert_eq!(resource_table.num_resources, 0);
        assert_eq!(resource_table.resource_offsets.len(), 0);
    }

    #[test]
    fn parse_resource_table_fw_rsc_carveout() {
        #[rustfmt::skip]
        let data = [
            0x00, 0x00, 0x00, 0x01, // version
            0x00, 0x00, 0x00, 0x01, // num_resources
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x14, // resource_offsets[0] == 20

            0x00, 0x00, 0x00, 0x00, // RSC_CARVEOUT == 0
            0xDE, 0xAD, 0xBE, 0xEF, // da == 0xDEADBEEF
            0xAA, 0xBB, 0xCC, 0xDD, // pa == 0xAABBCCDD
            0xAA, 0xAA, 0xAA, 0xAA, // len == 0xAAAAAAAA
            0x00, 0x00, 0x00, 0x00, // flags == 0x00000000
            0x00, 0x00, 0x00, 0x00, // reserved
            0x40, 0x00, 0x00, 0x00, // name: [u8;32] == "@"
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut offset = 0;

        let resource_table = ResourceTable::parse_at(BigEndian, Class::ELF32, &mut offset, &data)
            .expect("Failed to parse");

        assert_eq!(resource_table.version, 1);
        assert_eq!(resource_table.num_resources, 1);
        assert_eq!(resource_table.resource_offsets.len(), 1 * size_of::<u32>());

        let resource_carveout = resource_table
            .to_iter()
            .next()
            .expect("Could not get resource carveout");
        assert!(matches!(
            resource_carveout,
            FirmwareResource::Carveout(FirmwareResourceCarveout {
                da: 0xDEADBEEF,
                pa: 0xAABBCCDD,
                len: 0xAAAAAAAA,
                flags: 0x00000000,
                name: _
            })
        ));

        if let FirmwareResource::Carveout(resource_carveout) = resource_carveout {
            assert_eq!(resource_carveout.name[0], b'@');
        }
    }
    #[test]
    fn parse_resource_table_fw_rsc_devmem() {
        #[rustfmt::skip]
        let data = [
            0x01, 0x00, 0x00, 0x00, // version
            0x01, 0x00, 0x00, 0x00, // num_resources
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
            0x14, 0x00, 0x00, 0x00, // resource_offsets[0] == 20
                                    
            0x01, 0x00, 0x00, 0x00, // RSC_DEVMEM == 1
            0xEF, 0xBE, 0xAD, 0xDE, // da == 0xDEADBEEF
            0xDD, 0xCC, 0xBB, 0xAA, // pa == 0xAABBCCDD
            0xAA, 0xAA, 0xAA, 0xAA, // len == 0xAAAAAAAA
            0x00, 0x00, 0x00, 0x00, // flags == 0x00000000
            0x00, 0x00, 0x00, 0x00, // reserved
            0x40, 0x00, 0x00, 0x00, // name: [u8;32] == "@"
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let mut offset = 0;

        let resource_table = ResourceTable::parse_at(LittleEndian, Class::ELF32, &mut offset, &data)
            .expect("Failed to parse");

        assert_eq!(resource_table.version, 1);
        assert_eq!(resource_table.num_resources, 1);
        assert_eq!(resource_table.resource_offsets.len(), 1 * size_of::<u32>());

        let resource_devmem = resource_table
            .to_iter()
            .next()
            .expect("Could not get resource carveout");
        assert!(matches!(
            resource_devmem,
            FirmwareResource::Devmem(FirmwareResourceDevmem {
                da: 0xDEADBEEF,
                pa: 0xAABBCCDD,
                len: 0xAAAAAAAA,
                flags: 0x00000000,
                name: _
            })
        ));

        if let FirmwareResource::Devmem(resource_devmem) = resource_devmem {
            assert_eq!(resource_devmem.name[0], b'@');
        }
    }
}
