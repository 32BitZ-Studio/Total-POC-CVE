#![forbid(unsafe_code)]

use bytemuck::cast;
use elf::load;
use snp_types::{cpuid::CpuidPage, PageType, VmplPermissions};
use x86_64::structures::paging::PhysFrame;

mod elf;

#[derive(Debug)]
pub struct LoadCommand {
    pub physical_address: PhysFrame,
    pub vmpl1_perms: VmplPermissions,
    pub payload: LoadCommandPayload,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum LoadCommandPayload {
    Normal([u8; 0x1000]),
    Zero,
    Secrets,
    Cpuid(CpuidPage),
    Shared([u8; 0x1000]),
}

impl LoadCommandPayload {
    pub fn page_type(&self) -> Option<PageType> {
        match self {
            LoadCommandPayload::Normal(_) => Some(PageType::Normal),
            LoadCommandPayload::Zero => Some(PageType::Zero),
            LoadCommandPayload::Secrets => Some(PageType::Secrets),
            LoadCommandPayload::Cpuid(_) => Some(PageType::Cpuid),
            LoadCommandPayload::Shared(_) => None,
        }
    }

    pub fn bytes(&self) -> [u8; 0x1000] {
        match self {
            LoadCommandPayload::Normal(bytes) => *bytes,
            LoadCommandPayload::Zero => [0; 0x1000],
            LoadCommandPayload::Secrets => [0; 0x1000],
            LoadCommandPayload::Cpuid(cpuid) => cast(*cpuid),
            LoadCommandPayload::Shared(bytes) => *bytes,
        }
    }
}

pub fn generate_base_load_commands(kernel: &[u8]) -> impl Iterator<Item = LoadCommand> + '_ {
    load(kernel, VmplPermissions::empty())
}

pub fn generate_load_commands(kernel: &[u8]) -> (impl Iterator<Item = LoadCommand> + '_, [u8; 32]) {
    let base_load_commands = generate_base_load_commands(kernel);
    (base_load_commands, [0; 32])
}
