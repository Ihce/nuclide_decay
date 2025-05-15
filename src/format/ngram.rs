//! N-gram output formatter for instruction sequence analysis

use std::collections::HashMap;
use serde_json::json;
use crate::{Disassembly, DisassemblyError, Insn, Address};
use super::{DisassemblyFormatter, NgramFormatter, NgramParams};

impl DisassemblyFormatter for NgramFormatter {
    fn format(&self, disassembly: &Disassembly, _base_addr: Address) -> Result<String, DisassemblyError> {
        // Extract all instructions in proper order
        let instructions = match disassembly {
            Disassembly::Stream(insns) => insns.clone(),
            Disassembly::Cfg(blocks) => {
                // For CFG, we need to sort by address to maintain logical sequence
                let mut all_insns = Vec::new();
                for block in blocks {
                    all_insns.extend(block.insns.clone());
                }
                all_insns.sort_by_key(|insn| insn.addr);
                all_insns
            }
        };
        
        // Check if we have enough instructions for n-grams
        if instructions.len() < self.params.n {
            return Ok(json!({
                "n": self.params.n,
                "include_operands": self.params.include_operands,
                "ngrams": [],
                "warning": format!("Not enough instructions for {}-grams (found {})", 
                                self.params.n, instructions.len())
            }).to_string());
        }
        
        // Generate and count n-grams
        let mut ngram_counts = HashMap::new();
        let n = self.params.n;
        let include_operands = self.params.include_operands;
        
        for window in instructions.windows(n) {
            let ngram = if include_operands {
                // Include both mnemonic and operands
                window.iter()
                    .map(|insn| format!("{}_{}", insn.mnemonic, insn.operands))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                // Mnemonic only
                window.iter()
                    .map(|insn| insn.mnemonic.clone())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            
            *ngram_counts.entry(ngram).or_insert(0) += 1;
        }
        
        // Sort n-grams by frequency (descending)
        let mut ngrams = ngram_counts.into_iter().collect::<Vec<_>>();
        ngrams.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Convert to JSON
        let result = json!({
            "n": n,
            "include_operands": include_operands,
            "total_instructions": instructions.len(),
            "unique_ngrams": ngrams.len(),
            "ngrams": ngrams.into_iter().map(|(sequence, count)| {
                json!({
                    "sequence": sequence,
                    "count": count,
                    "percentage": (count as f64 / (instructions.len() - n + 1) as f64 * 100.0)
                })
            }).collect::<Vec<_>>()
        });
        
        Ok(serde_json::to_string_pretty(&result)
            .map_err(|e| DisassemblyError::Generic(format!("JSON serialization error: {}", e)))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Insn, Disassembly};
    
    #[test]
    fn test_ngram_generation() {
        // Create a simple stream of instructions
        let instructions = vec![
            Insn {
                addr: 0x1000,
                size: 1,
                mnemonic: "push".to_string(),
                operands: "ebp".to_string(),
                bytes: [0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Insn {
                addr: 0x1001,
                size: 3,
                mnemonic: "mov".to_string(),
                operands: "ebp, esp".to_string(),
                bytes: [0x89, 0xe5, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Insn {
                addr: 0x1004,
                size: 2,
                mnemonic: "sub".to_string(),
                operands: "esp, 0x10".to_string(),
                bytes: [0x83, 0xec, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Insn {
                addr: 0x1006,
                size: 1,
                mnemonic: "push".to_string(),
                operands: "ebx".to_string(),
                bytes: [0x53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Insn {
                addr: 0x1007,
                size: 1,
                mnemonic: "push".to_string(),
                operands: "esi".to_string(),
                bytes: [0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
        ];
        
        let disasm = Disassembly::Stream(instructions);
        
        // Create formatter with n=2
        let formatter = NgramFormatter::new(NgramParams {
            n: 2,
            include_operands: false,
        });
        
        // Format and parse the result
        let result = formatter.format(&disasm, 0x1000).unwrap();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        
        // Check that we got the right data
        assert_eq!(json["n"], 2);
        assert_eq!(json["include_operands"], false);
        
        // Should have "push push" and "mov sub" and "sub push" bigrams
        let ngrams = json["ngrams"].as_array().unwrap();
        
        // Find the "push push" bigram
        let push_push = ngrams.iter().find(|n| n["sequence"] == "push push").unwrap();
        assert_eq!(push_push["count"], 1);
        
        // Check total unique n-grams
        assert_eq!(json["unique_ngrams"], 4);
    }
}