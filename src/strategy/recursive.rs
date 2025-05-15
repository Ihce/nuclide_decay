//! Recursive descent disassembly strategy

use std::collections::{HashSet, VecDeque};
use crate::{Address, BasicBlock, Decoder, Disassembly, Insn, DisassemblyError};

/// Recursive-descent disassembly into a Control Flow Graph (CFG).
///
/// This strategy follows the control flow of the program, starting from a given entry point
/// (defaults to 0) and following branches to discover code. It creates a CFG representation
/// of the disassembled code.
///
/// # Arguments
/// * `image` - The binary image to disassemble
/// * `decoder` - The decoder to use for disassembly
///
/// # Returns
/// A CFG representation of the disassembled code
pub fn run(image: &[u8], decoder: &dyn Decoder) -> Result<Disassembly, DisassemblyError> {
    log::debug!("Starting recursive descent disassembly of {} bytes", image.len());
    
    let blocks = recursive_disassemble(image, decoder, 0)?;
    
    log::debug!("Recursive descent complete: {} basic blocks", blocks.len());
    
    Ok(Disassembly::Cfg(blocks))
}

/// Run recursive disassembly from a specific entry point
pub fn run_from(image: &[u8], decoder: &dyn Decoder, entry_point: Address) -> Result<Disassembly, DisassemblyError> {
    log::debug!("Starting recursive descent disassembly from 0x{:x}", entry_point);
    
    let blocks = recursive_disassemble(image, decoder, entry_point)?;
    
    log::debug!("Recursive descent complete: {} basic blocks", blocks.len());
    
    Ok(Disassembly::Cfg(blocks))
}

/// Core recursive disassembly algorithm
fn recursive_disassemble(image: &[u8], decoder: &dyn Decoder, entry_point: Address) -> Result<Vec<BasicBlock>, DisassemblyError> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut blocks = Vec::new();

    queue.push_back(entry_point);
    
    while let Some(addr) = queue.pop_front() {
        if !seen.insert(addr) { continue; }
        
        let mut insns = Vec::new();
        let mut at = addr;
        
        let mut is_block_end = false;
        
        while let Some(i) = decoder.decode(image, at) {
            // Add the instruction to the current basic block
            let size = i.size as Address;
            insns.push(i.clone());
            at += size;
            
            // Check if this is a branch instruction
            if is_branch(&i) {
                let targets = extract_branch_targets(&i);
                
                // Add branch targets to the work queue
                for &target in &targets {
                    if !seen.contains(&target) {
                        queue.push_back(target);
                    }
                }
                
                is_block_end = true;
                break;
            }
            
            // Check if this is a return instruction
            if is_return(&i) {
                is_block_end = true;
                break;
            }
        }
        
        // Only create a block if we found at least one instruction
        if !insns.is_empty() {
            // Get successor addresses
            let succs = if is_block_end {
                extract_branch_targets_from_last(&insns)
            } else {
                // If we didn't end with a branch/return, the successor is the next address
                vec![at]
            };
            
            blocks.push(BasicBlock {
                start: addr,
                insns,
                succs,
            });
        }
    }

    Ok(blocks)
}

/// Check if an instruction is a branch (conditional or unconditional)
fn is_branch(insn: &Insn) -> bool {
    // This is a simplified check that could be improved with architecture-specific logic
    let mnemonic = insn.mnemonic.to_lowercase();
    
    mnemonic.starts_with("j") ||       // x86 jumps
    mnemonic.starts_with("call") ||    // x86 calls
    mnemonic.starts_with("b") ||       // ARM branches
    mnemonic.starts_with("bl") ||      // ARM branch-and-link
    mnemonic.contains("branch") ||     // Generic branch keyword
    mnemonic.contains("jump")          // Generic jump keyword
}

/// Check if an instruction is a return
fn is_return(insn: &Insn) -> bool {
    let mnemonic = insn.mnemonic.to_lowercase();
    
    mnemonic == "ret" ||              // x86 return
    mnemonic == "bx lr" ||            // ARM return (branch to link register)
    mnemonic == "jr ra" ||            // MIPS return (jump to return address)
    mnemonic.contains("return")       // Generic return keyword
}

/// Extract branch targets from an instruction
fn extract_branch_targets(insn: &Insn) -> Vec<Address> {
    // More robust implementation using Capstone's instruction detail would be better
    // This string parsing approach is a simplification
    let ops = insn.operands.to_lowercase();
    
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

/// Extract branch targets from the last instruction in a block
fn extract_branch_targets_from_last(insns: &[Insn]) -> Vec<Address> {
    // If the block is empty, there are no targets
    if insns.is_empty() {
        return Vec::new();
    }
    
    // Get the last instruction
    let last = &insns[insns.len() - 1];
    
    // If it's a return, there are no targets
    if is_return(last) {
        return Vec::new();
    }
    
    // If it's a branch, extract its targets
    if is_branch(last) {
        return extract_branch_targets(last);
    }
    
    // If it's not a branch or return, the target is the next instruction
    vec![last.addr + last.size as Address]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::CapstoneDecoder;
    use crate::Architecture;
    
    #[test]
    fn test_recursive_disassembly_simple() {
        // Simple x86 code: mov eax, 1; ret
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        
        let decoder = CapstoneDecoder::for_architecture(Architecture::X86_32).unwrap();
        let result = run(&bytes, &decoder).unwrap();
        
        if let Disassembly::Cfg(blocks) = result {
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].insns.len(), 2);
            assert_eq!(blocks[0].insns[0].mnemonic, "mov");
            assert_eq!(blocks[0].insns[1].mnemonic, "ret");
            assert!(blocks[0].succs.is_empty()); // No successors for ret
        } else {
            panic!("Expected CFG disassembly");
        }
    }
    
    #[test]
    fn test_is_branch() {
        // Create a mock jump instruction
        let jump_insn = Insn {
            addr: 0,
            size: 2,
            mnemonic: "jmp".to_string(),
            operands: "0x1234".to_string(),
            bytes: [0xeb, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        
        assert!(is_branch(&jump_insn));
        
        // Create a mock non-branch instruction
        let non_branch_insn = Insn {
            addr: 0,
            size: 1,
            mnemonic: "nop".to_string(),
            operands: "".to_string(),
            bytes: [0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        
        assert!(!is_branch(&non_branch_insn));
    }
    
    #[test]
    fn test_extract_branch_targets() {
        // Create a mock jump instruction with a target
        let jump_insn = Insn {
            addr: 0,
            size: 5,
            mnemonic: "jmp".to_string(),
            operands: "0x1234".to_string(),
            bytes: [0xe9, 0x30, 0x12, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        
        let targets = extract_branch_targets(&jump_insn);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], 0x1234);
    }
}