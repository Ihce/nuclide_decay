//! Goblin-based multi-format binary parser.

use std::fmt;
use goblin::{elf, pe, Object};
use goblin::mach::{Mach, MachO, constants::cputype};

use crate::{Address, Architecture, BinaryMetadata, BinaryParser, Section, DisassemblyError};

/// A parser that handles ELF, PE, and Mach-O via Goblin.
#[derive(Debug, Default)]
pub struct GoblinParser;

impl GoblinParser {
    /// Construct a new GoblinParser.
    pub fn new() -> Self {
        GoblinParser
    }

    /// Parse an ELF image.
    fn parse_elf(&self, elf: elf::Elf, _img: &[u8]) -> Result<BinaryMetadata, DisassemblyError> {
        let arch = match elf.header.e_machine {
            elf::header::EM_386       => Architecture::X86_32,
            elf::header::EM_X86_64    => Architecture::X86_64,
            elf::header::EM_ARM       => Architecture::Arm,
            elf::header::EM_AARCH64   => Architecture::AArch64,
            elf::header::EM_MIPS      => Architecture::Mips32,
            elf::header::EM_RISCV     => {
                // Determine RISC-V bitness from ELF class
                match elf.header.e_ident[elf::header::EI_CLASS] {
                    elf::header::ELFCLASS32 => Architecture::RiscV32,
                    elf::header::ELFCLASS64 => Architecture::RiscV64,
                    _ => Architecture::Unknown,
                }
            },
            _                         => Architecture::Unknown,
        };

        // Gather all sections
        let mut sections = Vec::new();
        for sh in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                sections.push(Section::new(
                    name.to_string(),
                    sh.sh_addr,
                    sh.sh_size as usize,
                    sh.is_executable(),
                ));
            }
        }

        // Find the .text section
        let text_section = sections
            .iter()
            .find(|s| s.name == ".text")
            .map(|s| s.address);

        Ok(BinaryMetadata {
            architecture: arch,
            entry_point:  Some(elf.entry),
            sections,
            text_section,
        })
    }

    /// Parse a PE image.
    fn parse_pe(&self, pe: pe::PE<'_>, _img: &[u8]) -> Result<BinaryMetadata, DisassemblyError> {
        let arch = match pe.header.coff_header.machine {
            pe::header::COFF_MACHINE_X86    => Architecture::X86_32,
            pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
            pe::header::COFF_MACHINE_ARM    => Architecture::Arm,
            pe::header::COFF_MACHINE_ARM64  => Architecture::AArch64,
            _                                => Architecture::Unknown,
        };

        // Gather PE sections
        let mut sections = Vec::new();
        for sect in &pe.sections {
            let name = sect.name().unwrap_or("").to_string();
            let executable = (sect.characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE) != 0;
            sections.push(Section::new(
                name,
                sect.virtual_address as Address,
                sect.virtual_size  as usize,
                executable,
            ));
        }

        // Find ".text" (case‐insensitive)
        let text_section = sections
            .iter()
            .find(|s| s.name.to_lowercase().contains(".text"))
            .map(|s| s.address);

        Ok(BinaryMetadata {
            architecture: arch,
            entry_point:  Some(pe.entry as u64),
            sections,
            text_section,
        })
    }

    /// Parse a Mach-O binary
    fn parse_macho(&self, macho: &MachO) -> Result<BinaryMetadata, DisassemblyError> {
        let arch = match macho.header.cputype {
            cputype::CPU_TYPE_I386   => Architecture::X86_32,
            cputype::CPU_TYPE_X86_64 => Architecture::X86_64,
            cputype::CPU_TYPE_ARM    => Architecture::Arm,
            cputype::CPU_TYPE_ARM64  => Architecture::AArch64,
            _                        => Architecture::Unknown,
        };

        // For Mach-O, let's use a simpler approach with just segments for now
        // This avoids the nested section handling complexity
        let mut sections = Vec::new();
        let mut text_section = None;
        
        // For each segment
        for segment in &macho.segments {
            // Check if segment is executable - VM_PROT_EXECUTE is usually 0x4
            let is_executable = (segment.maxprot & 0x4) != 0;
            
            // We'll use the segment name for now
            let name = segment.name().unwrap_or("").to_string();
            let address = segment.vmaddr as Address;
            let size = segment.vmsize as usize;
            
            // Check if this segment contains text section
            if name.contains("__TEXT") || name.contains("text") {
                if text_section.is_none() {
                    text_section = Some(address);
                }
            }
            
            sections.push(Section::new(
                name,
                address,
                size,
                is_executable,
            ));
        }

        // Try to find an entry point
        let entry_point = Some(macho.entry as u64);

        Ok(BinaryMetadata {
            architecture: arch,
            entry_point,
            sections,
            text_section,
        })
    }

    /// Parse a Mach-O image.
    fn parse_mach(&self, m: Mach<'_>, _img: &[u8]) -> Result<BinaryMetadata, DisassemblyError> {
        match m {
            Mach::Binary(binary) => {
                self.parse_macho(&binary)
            },
            Mach::Fat(_) => {
                // For fat binaries, just use default metadata for now with Unknown architecture
                Ok(BinaryMetadata {
                    architecture: Architecture::Unknown,
                    entry_point: None,
                    sections: Vec::new(),
                    text_section: None,
                })
            }
        }
    }
}

impl fmt::Display for GoblinParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GoblinParser")
    }
}

impl BinaryParser for GoblinParser {
    fn parse(&self, data: &[u8]) -> Result<BinaryMetadata, DisassemblyError> {
        match Object::parse(data) {
            Ok(Object::Elf(elf)) => {
                self.parse_elf(elf, data)
            },
            Ok(Object::PE(pe)) => {
                self.parse_pe(pe, data)
            },
            Ok(Object::Mach(m)) => {
                self.parse_mach(m, data)
            },
            Ok(_) => Err(DisassemblyError::ParsingError("Unsupported file format".into())),
            Err(e) => Err(DisassemblyError::ParsingError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_raw() {
        let meta = BinaryMetadata::default_raw();
        assert_eq!(meta.architecture, Architecture::Unknown);
        assert!(meta.entry_point.is_none());
        assert!(meta.sections.is_empty());
        assert!(meta.text_section.is_none());
    }
    
    // We'd add more tests here with sample binaries for different formats
}