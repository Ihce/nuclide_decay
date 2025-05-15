//! Core IR, traits, metadata, and dispatch for the Nuclide Decay disassembler.
//!
//! This library provides a flexible framework for disassembling binary code across
//! multiple architectures and binary formats. It supports several disassembly strategies
//! and integrates with the Capstone disassembly engine.
//!
//! # Basic Usage
//!
//! ```rust,no_run
//! use std::fs;
//! use nuclide_decay::{
//!     parser::GoblinParser,
//!     decoder::CapstoneDecoder,
//!     strategy::Strategy,
//!     BinaryParser, // Import the trait to bring parse() method into scope
//! };
//!
//! // Read binary file
//! let binary_data = fs::read("path/to/binary").unwrap();
//!
//! // Parse the binary format
//! let parser = GoblinParser::new();
//! let metadata = parser.parse(&binary_data).unwrap();
//!
//! // Create a decoder for the detected architecture
//! let decoder = CapstoneDecoder::for_architecture(metadata.architecture).unwrap();
//!
//! // Disassemble executable sections
//! for (region_data, base_addr) in metadata.get_executable_data(&binary_data) {
//!     // Use linear sweep disassembly
//!     let disassembly = Strategy::Linear.run(region_data, &decoder).unwrap();
//!
//!     // Process the disassembly results
//!     // ...
//! }
//! ```

pub mod parser;
pub mod decoder;
pub mod strategy;
pub mod format;
mod large_tests;
#[cfg(feature = "extension-module")]
pub mod python;
/// Represents an address in memory
pub type Address = u64;

use std::fmt;

/// Maximum instruction size in bytes
pub const MAX_INSTRUCTION_SIZE: usize = 16;

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    /// Address of the instruction
    pub addr: Address,
    /// Size of the instruction in bytes
    pub size: u8,
    /// Instruction mnemonic (e.g., "mov", "add")
    pub mnemonic: String,
    /// Instruction operands as string representation
    pub operands: String,
    /// Raw bytes of the instruction (up to MAX_INSTRUCTION_SIZE)
    pub bytes: [u8; MAX_INSTRUCTION_SIZE],
}

impl Insn {
    /// Returns the instruction bytes, up to the actual instruction size.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.size as usize]
    }
    
    /// Returns true if this instruction is likely a branch instruction
    pub fn is_branch(&self) -> bool {
        let mnemonic = self.mnemonic.to_lowercase();
        
        mnemonic.starts_with("j") ||       // x86 jumps
        mnemonic.starts_with("call") ||    // x86 calls
        mnemonic.starts_with("b") ||       // ARM branches
        mnemonic.starts_with("bl") ||      // ARM branch-and-link
        mnemonic.contains("branch") ||     // Generic branch keyword
        mnemonic.contains("jump")          // Generic jump keyword
    }
    
    /// Returns true if this instruction is likely a return instruction
    pub fn is_return(&self) -> bool {
        let mnemonic = self.mnemonic.to_lowercase();
        
        mnemonic == "ret" ||              // x86 return
        mnemonic == "bx lr" ||            // ARM return (branch to link register)
        mnemonic == "jr ra" ||            // MIPS return (jump to return address)
        mnemonic.contains("return")       // Generic return keyword
    }
    
    /// Attempts to extract branch targets from this instruction
    pub fn branch_targets(&self) -> Vec<Address> {
        // This is a simplified approach - a real implementation would use Capstone's
        // detailed instruction information
        let ops = self.operands.to_lowercase();
        
        // Look for hexadecimal addresses (0x...)
        if let Some(idx) = ops.find("0x") {
            // Find the end of the hex value (space, comma, or end of string)
            let hex_str = &ops[idx+2..];
            let end_idx = hex_str.find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(hex_str.len());
                
            let hex = &hex_str[..end_idx];
            
            if let Ok(val) = u64::from_str_radix(hex, 16) {
                return vec![val];
            }
        }
        
        // No targets found
        Vec::new()
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}", self.mnemonic, self.operands)
    }
}

/// Decoder trait: architecture-specific disassembler.
pub trait Decoder: Send + Sync {
    /// Decode a single instruction at `at` offset.
    /// 
    /// # Arguments
    /// * `image` - The binary image to decode
    /// * `at` - Address offset into the image
    /// 
    /// # Returns
    /// Some(Insn) if an instruction was successfully decoded, None otherwise
    fn decode(&self, image: &[u8], at: Address) -> Option<Insn>;
}

/// One basic block for CFG strategies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// Starting address of the basic block
    pub start: Address,
    /// Instructions within this basic block
    pub insns: Vec<Insn>,
    /// Successor addresses (branch targets)
    pub succs: Vec<Address>,
}

impl BasicBlock {
    /// Create a new basic block
    pub fn new(start: Address) -> Self {
        Self {
            start,
            insns: Vec::new(),
            succs: Vec::new(),
        }
    }
    
    /// Get the address of the last instruction in the block
    pub fn end_address(&self) -> Option<Address> {
        self.insns.last().map(|insn| insn.addr + insn.size as Address)
    }
    
    /// Add an instruction to this basic block
    pub fn add_instruction(&mut self, insn: Insn) {
        self.insns.push(insn);
    }
    
    /// Set the successor addresses for this block
    pub fn set_successors(&mut self, succs: Vec<Address>) {
        self.succs = succs;
    }
    
    /// Get the last instruction in the block
    pub fn last_instruction(&self) -> Option<&Insn> {
        self.insns.last()
    }
    
    /// Get the size of the block in bytes
    pub fn size(&self) -> usize {
        self.insns.iter().map(|i| i.size as usize).sum()
    }
}

/// Unified disassembly output.
#[derive(Debug, Clone)]
pub enum Disassembly {
    /// Linear stream of instructions
    Stream(Vec<Insn>),
    /// Control flow graph of basic blocks
    Cfg(Vec<BasicBlock>),
}

impl Disassembly {
    /// Get the total number of instructions
    pub fn instruction_count(&self) -> usize {
        match self {
            Disassembly::Stream(insns) => insns.len(),
            Disassembly::Cfg(blocks) => blocks.iter().map(|b| b.insns.len()).sum(),
        }
    }
    
    /// Get all instructions as a flat vector
    pub fn all_instructions(&self) -> Vec<Insn> {
        match self {
            Disassembly::Stream(insns) => insns.clone(),
            Disassembly::Cfg(blocks) => {
                let mut result = Vec::new();
                for block in blocks {
                    result.extend(block.insns.clone());
                }
                result
            }
        }
    }
    
    /// Convert to a stream disassembly (losing CFG information)
    pub fn to_stream(&self) -> Disassembly {
        match self {
            Disassembly::Stream(_) => self.clone(),
            Disassembly::Cfg(_) => Disassembly::Stream(self.all_instructions()),
        }
    }
}

/// Supported architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Architecture {
    /// 32-bit x86
    X86_32,
    /// 64-bit x86
    X86_64,
    /// ARM (32-bit)
    Arm,
    /// ARM Thumb mode
    Thumb,
    /// AArch64 (ARM 64-bit)
    AArch64,
    /// MIPS 32-bit
    Mips32,
    /// RISC-V 32-bit
    RiscV32,
    /// RISC-V 64-bit
    RiscV64,
    /// PowerPC 32-bit
    Ppc32,
    /// Unknown architecture
    Unknown,
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Architecture::X86_32 => write!(f, "x86-32"),
            Architecture::X86_64 => write!(f, "x86-64"),
            Architecture::Arm => write!(f, "ARM"),
            Architecture::Thumb => write!(f, "Thumb"),
            Architecture::AArch64 => write!(f, "AArch64"),
            Architecture::Mips32 => write!(f, "MIPS32"),
            Architecture::RiscV32 => write!(f, "RISC-V 32"),
            Architecture::RiscV64 => write!(f, "RISC-V 64"),
            Architecture::Ppc32 => write!(f, "PowerPC 32"),
            Architecture::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A section in the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Section name
    pub name: String,
    /// Starting address of the section
    pub address: Address,
    /// Size of the section in bytes
    pub size: usize,
    /// Whether this section contains executable code
    pub executable: bool,
}

impl Section {
    /// Create a new section
    pub fn new(name: String, address: Address, size: usize, executable: bool) -> Self {
        Self {
            name,
            address,
            size,
            executable,
        }
    }
    
    /// Get the end address of this section
    pub fn end_address(&self) -> Address {
        self.address + self.size as Address
    }
}

/// Metadata describing a parsed binary.
#[derive(Debug, Clone)]
pub struct BinaryMetadata {
    /// Detected architecture
    pub architecture: Architecture,
    /// Entry point address, if available
    pub entry_point: Option<Address>,
    /// List of sections found in the binary
    pub sections: Vec<Section>,
    /// Address of the .text section, if found
    pub text_section: Option<Address>,
}

impl BinaryMetadata {
    /// Fallback metadata when no headers could be parsed.
    pub fn default_raw() -> Self {
        Self {
            architecture: Architecture::Unknown,
            entry_point: None,
            sections: Vec::new(),
            text_section: None,
        }
    }

    /// Pick a reasonable base address (entry point, text section, or zero).
    pub fn get_base_address(&self) -> Address {
        self.entry_point.or(self.text_section).unwrap_or(0)
    }

    /// Return all executable regions (or whole file if none).
    pub fn get_executable_data<'a>(
        &'a self,
        img: &'a [u8],
    ) -> Vec<(&'a [u8], Address)> {
        // Common section names by format
        const ELF_TEXT: &str = ".text";
        const PE_TEXT: [&str; 2] = [".text", "CODE"];
        const MACHO_TEXT: [&str; 3] = ["__TEXT,__text", "__text", "__TEXT"];
        
        // Check for common text section names first
        let common_names = [ELF_TEXT, PE_TEXT[0], PE_TEXT[1], MACHO_TEXT[0], MACHO_TEXT[1], MACHO_TEXT[2]];
        
        for name in common_names {
            if let Some(section) = self.find_section(name) {
                let start = section.address as usize;
                if start < img.len() {
                    let end = (start + section.size).min(img.len());
                    println!("Found '{}' section at 0x{:x} (size: {} bytes)", 
                            name, section.address, end - start);
                    return vec![(&img[start..end], section.address)];
                }
            }
        }
        
        // If no specific section found, check for any section with "text" in name (case insensitive)
        for section in &self.sections {
            if section.name.to_lowercase().contains("text") && section.executable {
                let start = section.address as usize;
                if start < img.len() {
                    let end = (start + section.size).min(img.len());
                    println!("Using section '{}' at 0x{:x} (size: {} bytes)",
                            section.name, section.address, end - start);
                    return vec![(&img[start..end], section.address)];
                }
            }
        }
        
        // If no text sections found but text_section address exists in metadata
        if let Some(text_addr) = self.text_section {
            if let Some(section) = self.sections.iter().find(|s| s.address == text_addr) {
                let start = section.address as usize;
                if start < img.len() {
                    let end = (start + section.size).min(img.len());
                    println!("Using text section from metadata at 0x{:x} (size: {} bytes)", 
                            text_addr, end - start);
                    return vec![(&img[start..end], text_addr)];
                }
            }
        }
        
        // Fallback: use smallest executable section
        // (This is often a good heuristic to avoid large data sections)
        let smallest_exec_section = self.sections.iter()
            .filter(|s| s.executable)
            .min_by_key(|s| s.size);
        
        if let Some(section) = smallest_exec_section {
            let start = section.address as usize;
            if start < img.len() {
                let end = (start + section.size).min(img.len());
                println!("Using smallest executable section '{}' at 0x{:x} (size: {} bytes)",
                        section.name, section.address, end - start);
                return vec![(&img[start..end], section.address)];
            }
        }
        
        // Last resort fallback: use first executable section
        let exec_secs: Vec<_> = self.sections.iter()
            .filter(|s| s.executable)
            .collect();
        
        if !exec_secs.is_empty() {
            let section = exec_secs[0];
            let start = section.address as usize;
            if start < img.len() {
                let end = (start + section.size).min(img.len());
                println!("Using first executable section '{}' at 0x{:x} (size: {} bytes)",
                        section.name, section.address, end - start);
                return vec![(&img[start..end], section.address)];
            }
        }
        
        // Absolute fallback: whole file
        println!("No suitable executable sections found, using whole file");
        vec![(img, 0)]
    }
    
    /// Find a section by name
    pub fn find_section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }
    
    /// Get all executable sections
    pub fn executable_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.executable).collect()
    }
}

/// Parser trait: turn raw bytes into `BinaryMetadata`.
pub trait BinaryParser: Send + Sync {
    /// Parse binary data into metadata
    /// 
    /// # Arguments
    /// * `data` - The binary data to parse
    /// 
    /// # Returns
    /// Result containing BinaryMetadata if parsing was successful
    fn parse(&self, data: &[u8]) -> Result<BinaryMetadata, DisassemblyError>;
}

/// Error type for disassembly operations
#[derive(Debug, thiserror::Error)]
pub enum DisassemblyError {
    /// Failed to parse binary format
    #[error("Failed to parse binary format: {0}")]
    ParsingError(String),
    
    /// Decoder error
    #[error("Decoder error: {0}")]
    DecoderError(String),
    
    /// Unsupported architecture
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(Architecture),
    
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// Generic error
    #[error("{0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_insn_bytes() {
        let insn = Insn {
            addr: 0x1000,
            size: 3,
            mnemonic: "add".to_string(),
            operands: "eax, ebx".to_string(),
            bytes: [0x01, 0xd8, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        
        assert_eq!(insn.bytes(), &[0x01, 0xd8, 0x90]);
    }
    
    #[test]
    fn test_basic_block_operations() {
        let mut block = BasicBlock::new(0x1000);
        
        // Add two instructions
        block.add_instruction(Insn {
            addr: 0x1000,
            size: 2,
            mnemonic: "mov".to_string(),
            operands: "eax, 1".to_string(),
            bytes: [0xb8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });
        
        block.add_instruction(Insn {
            addr: 0x1002,
            size: 1,
            mnemonic: "ret".to_string(),
            operands: "".to_string(),
            bytes: [0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });
        
        // Test end address
        assert_eq!(block.end_address(), Some(0x1003));
        
        // Test last instruction
        assert_eq!(block.last_instruction().unwrap().mnemonic, "ret");
        
        // Test size
        assert_eq!(block.size(), 3);
    }
    
    #[test]
    fn test_disassembly_instruction_count() {
        // Create a stream disassembly
        let stream = Disassembly::Stream(vec![
            Insn {
                addr: 0x1000,
                size: 1,
                mnemonic: "nop".to_string(),
                operands: "".to_string(),
                bytes: [0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Insn {
                addr: 0x1001,
                size: 1,
                mnemonic: "nop".to_string(),
                operands: "".to_string(),
                bytes: [0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
        ]);
        
        assert_eq!(stream.instruction_count(), 2);
        
        // Create a CFG disassembly
        let cfg = Disassembly::Cfg(vec![
            BasicBlock {
                start: 0x1000,
                insns: vec![
                    Insn {
                        addr: 0x1000,
                        size: 1,
                        mnemonic: "nop".to_string(),
                        operands: "".to_string(),
                        bytes: [0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    },
                ],
                succs: vec![0x1001],
            },
            BasicBlock {
                start: 0x1001,
                insns: vec![
                    Insn {
                        addr: 0x1001,
                        size: 1,
                        mnemonic: "ret".to_string(),
                        operands: "".to_string(),
                        bytes: [0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    },
                ],
                succs: vec![],
            },
        ]);
        
        assert_eq!(cfg.instruction_count(), 2);
    }

    
}