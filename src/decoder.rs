//! Capstone-based instruction decoders for multiple architectures.

use std::fmt;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use capstone::{Capstone, prelude::BuildsCapstone};
use capstone::arch::x86::ArchMode as X86Mode;
use capstone::arch::arm::ArchMode as ArmMode;
use capstone::arch::arm64::ArchMode as Arm64Mode;
use capstone::arch::mips::ArchMode as MipsMode;
use capstone::arch::ppc::ArchMode as PpcMode;
use capstone::arch::riscv::ArchMode as RiscVMode;
use capstone::{Arch, Mode, Endian, NO_EXTRA_MODE};

use crate::{Address, Decoder, Insn, Architecture, MAX_INSTRUCTION_SIZE};

/// Errors that can occur during decoding
#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    /// Capstone error
    #[error("Capstone error: {0}")]
    CapstoneError(#[from] capstone::Error),
    
    /// Invalid offset
    #[error("Invalid offset: {0} is outside the image bounds")]
    InvalidOffset(Address),
    
    /// Unsupported architecture
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(Architecture),
}

/// A Capstone-based decoder for all supported ISAs.
#[derive(Debug)]
pub enum CapstoneDecoder {
    X86_32(Capstone),
    X86_64(Capstone),
    Arm(Capstone),
    Thumb(Capstone),
    AArch64(Capstone),
    Mips32(Capstone),
    RiscV32(Capstone),
    RiscV64(Capstone),
    Ppc32(Capstone),
}

thread_local! {
    // Simple cache for Capstone instances - key is (arch, mode, endian)
    static CS_POOL: RefCell<HashMap<(Arch, Mode, Endian), Arc<Capstone>>> = 
        RefCell::new(HashMap::new());
}

// SAFETY: Capstone's C‐API handle is thread‐safe if you never call
// `disasm_all` concurrently on the *same* handle.
unsafe impl Send for CapstoneDecoder {}
unsafe impl Sync for CapstoneDecoder {}

impl CapstoneDecoder {
    /// Build one decoder for each supported ISA.
    pub fn all() -> Result<Vec<CapstoneDecoder>, DecoderError> {
        let decoders = vec![
            CapstoneDecoder::X86_32(Self::build_x86_32()?),
            CapstoneDecoder::X86_64(Self::build_x86_64()?),
            CapstoneDecoder::Arm(Self::build_arm()?),
            CapstoneDecoder::Thumb(Self::build_thumb()?),
            CapstoneDecoder::AArch64(Self::build_aarch64()?),
            CapstoneDecoder::Mips32(Self::build_mips32()?),
            CapstoneDecoder::RiscV32(Self::build_riscv32()?),
            CapstoneDecoder::RiscV64(Self::build_riscv64()?),
            CapstoneDecoder::Ppc32(Self::build_ppc32()?),
        ];
        
        Ok(decoders)
    }
    
    /// Create a decoder for a specific architecture
    pub fn for_architecture(arch: Architecture) -> Result<Self, DecoderError> {
        match arch {
            Architecture::X86_32 => Ok(CapstoneDecoder::X86_32(Self::build_x86_32()?)),
            Architecture::X86_64 => Ok(CapstoneDecoder::X86_64(Self::build_x86_64()?)),
            Architecture::Arm => Ok(CapstoneDecoder::Arm(Self::build_arm()?)),
            Architecture::Thumb => Ok(CapstoneDecoder::Thumb(Self::build_thumb()?)),
            Architecture::AArch64 => Ok(CapstoneDecoder::AArch64(Self::build_aarch64()?)),
            Architecture::Mips32 => Ok(CapstoneDecoder::Mips32(Self::build_mips32()?)),
            Architecture::RiscV32 => Ok(CapstoneDecoder::RiscV32(Self::build_riscv32()?)),
            Architecture::RiscV64 => Ok(CapstoneDecoder::RiscV64(Self::build_riscv64()?)),
            Architecture::Ppc32 => Ok(CapstoneDecoder::Ppc32(Self::build_ppc32()?)),
            Architecture::Unknown => Err(DecoderError::UnsupportedArchitecture(arch)),
        }
    }

    /// Build an x86 32-bit decoder
    pub fn build_x86_32() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .x86()
            .mode(X86Mode::Mode32)
            .detail(false)
            .build()?)
    }

    /// Build an x86 64-bit decoder
    pub fn build_x86_64() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .x86()
            .mode(X86Mode::Mode64)
            .detail(false)
            .build()?)
    }

    /// Build an ARM (ARM mode) decoder
    pub fn build_arm() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .arm()
            .mode(ArmMode::Arm)
            .detail(false)
            .build()?)
    }

    /// Build an ARM (Thumb mode) decoder
    pub fn build_thumb() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .arm()
            .mode(ArmMode::Thumb)
            .detail(false)
            .build()?)
    }

    /// Build an AArch64 decoder
    pub fn build_aarch64() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .arm64()
            .mode(Arm64Mode::Arm)
            .detail(false)
            .build()?)
    }

    /// Build a MIPS32 little-endian decoder
    pub fn build_mips32() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .mips()
            .mode(MipsMode::Mips32)
            .detail(false)
            .build()?)
    }

    /// Build a RISC-V 32-bit decoder
    pub fn build_riscv32() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .riscv()
            .mode(RiscVMode::RiscV32)
            .detail(false)
            .build()?)
    }

    /// Build a RISC-V 64-bit decoder
    pub fn build_riscv64() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .riscv()
            .mode(RiscVMode::RiscV64)
            .detail(false)
            .build()?)
    }

    /// Build a PPC32 decoder
    pub fn build_ppc32() -> Result<Capstone, DecoderError> {
        Ok(Capstone::new()
            .ppc()
            .mode(PpcMode::Mode32)
            .detail(false)
            .build()?)
    }
    
    /// Get the architecture of this decoder
    pub fn architecture(&self) -> Architecture {
        match self {
            CapstoneDecoder::X86_32(_)  => Architecture::X86_32,
            CapstoneDecoder::X86_64(_)  => Architecture::X86_64,
            CapstoneDecoder::Arm(_)     => Architecture::Arm,
            CapstoneDecoder::Thumb(_)   => Architecture::Thumb,
            CapstoneDecoder::AArch64(_) => Architecture::AArch64,
            CapstoneDecoder::Mips32(_)  => Architecture::Mips32,
            CapstoneDecoder::RiscV32(_) => Architecture::RiscV32,
            CapstoneDecoder::RiscV64(_) => Architecture::RiscV64,
            CapstoneDecoder::Ppc32(_)   => Architecture::Ppc32,
        }
    }
    
    /// Get Arch, Mode, Endian for this architecture
    fn get_arch_mode_endian(&self) -> (Arch, Mode, Endian) {
        match self {
            CapstoneDecoder::X86_32(_)  => (Arch::X86, Mode::Mode32, Endian::Little),
            CapstoneDecoder::X86_64(_)  => (Arch::X86, Mode::Mode64, Endian::Little),
            CapstoneDecoder::Arm(_)     => (Arch::ARM, Mode::Arm, Endian::Little),
            CapstoneDecoder::Thumb(_)   => (Arch::ARM, Mode::Thumb, Endian::Little),
            CapstoneDecoder::AArch64(_) => (Arch::ARM64, Mode::Arm, Endian::Little),
            CapstoneDecoder::Mips32(_)  => (Arch::MIPS, Mode::Mips32, Endian::Little),
            CapstoneDecoder::RiscV32(_) => (Arch::RISCV, Mode::RiscV32, Endian::Little),
            CapstoneDecoder::RiscV64(_) => (Arch::RISCV, Mode::RiscV64, Endian::Little),
            CapstoneDecoder::Ppc32(_)   => (Arch::PPC, Mode::Mode32, Endian::Big),
        }
    }
}

impl fmt::Display for CapstoneDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapstoneDecoder::{}", self.architecture())
    }
}

impl Decoder for CapstoneDecoder {
    fn decode(&self, image: &[u8], at: Address) -> Option<Insn> {
        let offset = at as usize;
        if offset >= image.len() {
            return None;
        }

        // Only look at a small slice (16 bytes max)
        let end = std::cmp::min(offset + 16, image.len());
        let slice = &image[offset..end];
        
        // Get the architecture, mode, and endian for this decoder
        let (arch, mode, endian) = self.get_arch_mode_endian();
        
        // Use thread-local cache for better performance
        let cs = CS_POOL.with(|cell| {
            let mut map = cell.borrow_mut();
            map.entry((arch, mode, endian))
                .or_insert_with(|| {
                    Arc::new(
                        Capstone::new_raw(arch, mode, NO_EXTRA_MODE, Some(endian))
                            .expect("valid arch/mode combo"),
                    )
                })
                .clone()
        });

        // Store the result first to avoid lifetime issues
        let disasm_result = Arc::as_ref(&cs).disasm_all(slice, at).ok()?;
        let mut it = disasm_result.iter();
        let i = it.next()?;
        
        // Ensure instruction starts at the address we requested
        if i.address() != at {
            return None;
        }
        
        // Copy up to MAX_INSTRUCTION_SIZE bytes of encoding
        let mut bytes = [0u8; MAX_INSTRUCTION_SIZE];
        for (j, b) in i.bytes().iter().enumerate().take(MAX_INSTRUCTION_SIZE) {
            bytes[j] = *b;
        }

        Some(Insn {
            addr:     i.address(),
            size:     i.bytes().len() as u8,
            mnemonic: i.mnemonic().unwrap_or("").to_string(),
            operands: i.op_str().unwrap_or("").to_string(),
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_architecture_mapping() {
        // Sample test to ensure architecture mapping works
        let decoder = CapstoneDecoder::for_architecture(Architecture::X86_64).unwrap();
        assert_eq!(decoder.architecture(), Architecture::X86_64);
    }
    
    #[test]
    fn test_x86_decode() {
        // Test decoding a simple x86 instruction (mov eax, 1)
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00];
        let decoder = CapstoneDecoder::for_architecture(Architecture::X86_32).unwrap();
        
        let insn = decoder.decode(&bytes, 0).unwrap();
        assert_eq!(insn.mnemonic, "mov");
        assert_eq!(insn.size, 5);
        
        // Test that we can get bytes back
        assert_eq!(insn.bytes(), &bytes);
    }
}