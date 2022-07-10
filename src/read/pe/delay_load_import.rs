use core::fmt::Debug;

use crate::read::{Bytes, ReadError, Result};
use crate::{pe, LittleEndian as LE, U16Bytes};

use super::{ImageNtHeaders, ImageThunkData, Import, ImportThunkList};

/// Information for parsing a PE import table.
#[derive(Debug, Clone)]
pub struct DelayLoadImportTable<'data> {
    section_data: Bytes<'data>,
    section_address: u32,
    import_address: u32,
}

impl<'data> DelayLoadImportTable<'data> {
    /// Create a new import table parser.
    ///
    /// The import descriptors start at `import_address`.
    /// This table works in the same way the import table does: descriptors will be
    /// parsed until a null entry.
    ///
    /// `section_data` should be from the section containing `import_address`, and
    /// `section_address` should be the address of that section. Pointers within the
    /// descriptors and thunks may point to anywhere within the section data.
    pub fn new(section_data: &'data [u8], section_address: u32, import_address: u32) -> Self {
        DelayLoadImportTable {
            section_data: Bytes(section_data),
            section_address,
            import_address,
        }
    }

    /// Return an iterator for the import descriptors.
    pub fn descriptors(&self) -> Result<DelayLoadDescriptorIterator<'data>> {
        let offset = self.import_address.wrapping_sub(self.section_address);
        let mut data = self.section_data;
        data.skip(offset as usize)
            .read_error("Invalid PE delay-load import descriptor address")?;
        Ok(DelayLoadDescriptorIterator { data })
    }

    /// Return a library name given its address.
    ///
    /// This address may be from [`pe::ImageImportDescriptor::name`].
    pub fn name(&self, address: u32) -> Result<&'data [u8]> {
        self.section_data
            .read_string_at(address.wrapping_sub(self.section_address) as usize)
            .read_error("Invalid PE import descriptor name")
    }

    /// Return a list of thunks given its address.
    ///
    /// This address may be from [`pe::ImageImportDescriptor::original_first_thunk`]
    /// or [`pe::ImageImportDescriptor::first_thunk`].
    pub fn thunks(&self, address: u32) -> Result<ImportThunkList<'data>> {
        let offset = address.wrapping_sub(self.section_address);
        let mut data = self.section_data;
        data.skip(offset as usize)
            .read_error("Invalid PE delay load import thunk table address")?;
        Ok(ImportThunkList { data })
    }

    /// Parse a thunk.
    pub fn import<Pe: ImageNtHeaders>(&self, thunk: Pe::ImageThunkData) -> Result<Import<'data>> {
        if thunk.is_ordinal() {
            Ok(Import::Ordinal(thunk.ordinal()))
        } else {
            let (hint, name) = self.hint_name(thunk.address())?;
            Ok(Import::Name(hint, name))
        }
    }

    /// Return the hint and name at the given address.
    ///
    /// This address may be from [`pe::ImageThunkData32`] or [`pe::ImageThunkData64`].
    ///
    /// The hint is an index into the export name pointer table in the target library.
    pub fn hint_name(&self, address: u32) -> Result<(u16, &'data [u8])> {
        let offset = address.wrapping_sub(self.section_address);
        let mut data = self.section_data;
        data.skip(offset as usize)
            .read_error("Invalid PE delay load import thunk address")?;
        let hint = data
            .read::<U16Bytes<LE>>()
            .read_error("Missing PE delay load import thunk hint")?
            .get(LE);
        let name = data
            .read_string()
            .read_error("Missing PE delay load import thunk name")?;
        Ok((hint, name))
    }
}

/// A fallible iterator for the descriptors in the delay-load data directory.
#[derive(Debug, Clone)]
pub struct DelayLoadDescriptorIterator<'data> {
    data: Bytes<'data>,
}

impl<'data> DelayLoadDescriptorIterator<'data> {
    /// Return the next descriptor.
    ///
    /// Returns `Ok(None)` when a null descriptor is found.
    pub fn next(&mut self) -> Result<Option<&'data pe::ImageDelayloadDescriptor>> {
        let import_desc = self
            .data
            .read::<pe::ImageDelayloadDescriptor>()
            .read_error("Missing PE null delay-load import descriptor")?;
        if import_desc.is_null() {
            Ok(None)
        } else {
            Ok(Some(import_desc))
        }
    }
}
