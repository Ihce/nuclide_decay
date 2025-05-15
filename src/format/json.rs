//! JSON and JSON Lines output formatters

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

use crate::{Disassembly, DisassemblyError, Insn, BasicBlock, Address};
use super::DisassemblyFormatter;

/// Serializable instruction for JSON output
#[derive(Serialize, Deserialize)]
struct InstructionJson {
    /// Address of the instruction
    address: String,
    /// Size of the instruction in bytes
    size: u8,
    /// Mnemonic (e.g., "mov", "add")
    mnemonic: String,
    /// Operands
    operands: String,
    /// Bytes of the instruction as hex string
    bytes: String,
}

/// Serializable basic block for JSON output
#[derive(Serialize, Deserialize)]
struct BasicBlockJson {
    /// Starting address of the block
    start: String,
    /// Instructions in this block
    instructions: Vec<InstructionJson>,
    /// Successor blocks
    successors: Vec<String>,
}

/// Serializable section for JSON output
#[derive(Serialize, Deserialize)]
struct SectionJson {
    /// Base address of the section
    base_address: String,
    /// Type of disassembly ("stream" or "cfg")
    #[serde(rename = "type")]
    disasm_type: String,
    /// Instructions (for Stream disassembly)
    #[serde(skip_serializing_if = "Option::is_none")]
    instructions: Option<Vec<InstructionJson>>,
    /// Basic blocks (for CFG disassembly)
    #[serde(skip_serializing_if = "Option::is_none")]
    blocks: Option<Vec<BasicBlockJson>>,
}

/// Serializable disassembly result for JSON output
#[derive(Serialize, Deserialize)]
struct DisassemblyJson {
    /// Sections in the disassembly
    sections: Vec<SectionJson>,
}

impl DisassemblyFormatter for super::JsonFormatter {
    fn format(&self, disassembly: &Disassembly, base_addr: Address) -> Result<String, DisassemblyError> {
        let section = match disassembly {
            Disassembly::Stream(insns) => {
                let instructions = insns.iter().map(instruction_to_json).collect();
                
                SectionJson {
                    base_address: format!("0x{:x}", base_addr),
                    disasm_type: "stream".to_string(),
                    instructions: Some(instructions),
                    blocks: None,
                }
            },
            Disassembly::Cfg(blocks) => {
                let blocks_json = blocks.iter().map(block_to_json).collect();
                
                SectionJson {
                    base_address: format!("0x{:x}", base_addr),
                    disasm_type: "cfg".to_string(),
                    instructions: None,
                    blocks: Some(blocks_json),
                }
            }
        };
        
        let result = DisassemblyJson {
            sections: vec![section],
        };
        
        serde_json::to_string_pretty(&result)
            .map_err(|e| DisassemblyError::Generic(format!("JSON serialization error: {}", e)))
    }
}

impl DisassemblyFormatter for super::JsonLinesFormatter {
    fn format(&self, disassembly: &Disassembly, base_addr: Address) -> Result<String, DisassemblyError> {
        let mut output = String::new();
        let base_addr_str = format!("0x{:x}", base_addr);
        
        match disassembly {
            Disassembly::Stream(insns) => {
                for insn in insns {
                    let instruction = json!({
                        "type": "instruction",
                        "base_address": base_addr_str,
                        "address": format!("0x{:x}", insn.addr),
                        "size": insn.size,
                        "mnemonic": insn.mnemonic,
                        "operands": insn.operands,
                        "bytes": insn.bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
                    });
                    
                    output.push_str(&serde_json::to_string(&instruction)
                        .map_err(|e| DisassemblyError::Generic(format!("JSON serialization error: {}", e)))?);
                    output.push('\n');
                }
            },
            Disassembly::Cfg(blocks) => {
                // First output blocks
                for block in blocks {
                    let block_json = json!({
                        "type": "block",
                        "base_address": base_addr_str,
                        "start": format!("0x{:x}", block.start),
                        "successors": block.succs.iter().map(|succ| format!("0x{:x}", succ)).collect::<Vec<_>>()
                    });
                    
                    output.push_str(&serde_json::to_string(&block_json)
                        .map_err(|e| DisassemblyError::Generic(format!("JSON serialization error: {}", e)))?);
                    output.push('\n');
                    
                    // Then output instructions for this block
                    for insn in &block.insns {
                        let instruction = json!({
                            "type": "instruction",
                            "base_address": base_addr_str,
                            "block_start": format!("0x{:x}", block.start),
                            "address": format!("0x{:x}", insn.addr),
                            "size": insn.size,
                            "mnemonic": insn.mnemonic,
                            "operands": insn.operands,
                            "bytes": insn.bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
                        });
                        
                        output.push_str(&serde_json::to_string(&instruction)
                            .map_err(|e| DisassemblyError::Generic(format!("JSON serialization error: {}", e)))?);
                        output.push('\n');
                    }
                }
            }
        }
        
        Ok(output)
    }
}

/// Convert an instruction to JSON format
fn instruction_to_json(insn: &Insn) -> InstructionJson {
    InstructionJson {
        address: format!("0x{:x}", insn.addr),
        size: insn.size,
        mnemonic: insn.mnemonic.clone(),
        operands: insn.operands.clone(),
        bytes: insn.bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
    }
}

/// Convert a basic block to JSON format
fn block_to_json(block: &BasicBlock) -> BasicBlockJson {
    BasicBlockJson {
        start: format!("0x{:x}", block.start),
        instructions: block.insns.iter().map(instruction_to_json).collect(),
        successors: block.succs.iter().map(|succ| format!("0x{:x}", *succ)).collect(),
    }
}