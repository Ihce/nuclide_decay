//! CSV output formatter

use crate::{Disassembly, DisassemblyError, Address};
use super::DisassemblyFormatter;

impl DisassemblyFormatter for super::CsvFormatter {
    fn format(&self, disassembly: &Disassembly, base_addr: Address) -> Result<String, DisassemblyError> {
        let mut output = String::new();
        let base_addr_str = format!("0x{:x}", base_addr);
        
        // CSV header
        output.push_str("base_address,section_type,block_address,address,size,mnemonic,operands,bytes\n");
        
        match disassembly {
            Disassembly::Stream(insns) => {
                let section_type = "stream";
                
                for insn in insns {
                    let addr = format!("0x{:x}", insn.addr);
                    let bytes = insn.bytes()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    
                    // Escape fields that might contain commas
                    let mnemonic = escape_csv_field(&insn.mnemonic);
                    let operands = escape_csv_field(&insn.operands);
                    
                    // Write CSV line
                    output.push_str(&format!(
                        "{},{},\"\",{},{},{},{},{}\n",
                        base_addr_str, section_type, addr, insn.size, 
                        mnemonic, operands, bytes
                    ));
                }
            },
            Disassembly::Cfg(blocks) => {
                let section_type = "cfg";
                
                for block in blocks {
                    let block_addr = format!("0x{:x}", block.start);
                    
                    for insn in &block.insns {
                        let addr = format!("0x{:x}", insn.addr);
                        let bytes = insn.bytes()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        
                        // Escape fields that might contain commas
                        let mnemonic = escape_csv_field(&insn.mnemonic);
                        let operands = escape_csv_field(&insn.operands);
                        
                        // Write CSV line
                        output.push_str(&format!(
                            "{},{},{},{},{},{},{},{}\n",
                            base_addr_str, section_type, block_addr, addr, insn.size, 
                            mnemonic, operands, bytes
                        ));
                    }
                }
            }
        }
        
        Ok(output)
    }
}

/// Helper function to escape a field for CSV output
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('\"') || field.contains('\n') {
        // Need to escape
        let escaped = field.replace('\"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        field.to_string()
    }
}