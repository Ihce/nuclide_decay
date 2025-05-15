//! Output format module implementation

mod json;
mod csv;
mod ngram;

pub use self::json::*;
pub use self::csv::*;
pub use self::ngram::*;

use crate::{Address, Disassembly, DisassemblyError};
use std::fmt;
use std::str::FromStr;
use clap::ValueEnum;

/// Supported output formats for disassembly results
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Plain text output (default)
    Text,
    /// JSON format (hierarchical)
    Json,
    /// JSON Lines format (one JSON object per line)
    JsonLines,
    /// CSV format (comma-separated values)
    Csv,
    /// N-gram format for instruction sequence analysis
    Ngram,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::JsonLines => write!(f, "jsonl"),
            OutputFormat::Csv => write!(f, "csv"),
            OutputFormat::Ngram => write!(f, "ngram"),
        }
    }
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "jsonl" | "jsonlines" => Ok(OutputFormat::JsonLines),
            "csv" => Ok(OutputFormat::Csv),
            "ngram" | "ngrams" => Ok(OutputFormat::Ngram),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

impl OutputFormat {
    /// Get the default output format
    pub fn default() -> Self {
        OutputFormat::Text
    }
    
    /// Get all available output formats
    pub fn available_formats() -> &'static [Self] {
        &[
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::JsonLines,
            OutputFormat::Csv,
            OutputFormat::Ngram,
        ]
    }
    
    /// Get a formatter for this output format
    pub fn get_formatter(&self, ngram_params: Option<NgramParams>) -> Box<dyn DisassemblyFormatter> {
        match self {
            OutputFormat::Text => Box::new(TextFormatter),
            OutputFormat::Json => Box::new(JsonFormatter),
            OutputFormat::JsonLines => Box::new(JsonLinesFormatter),
            OutputFormat::Csv => Box::new(CsvFormatter),
            OutputFormat::Ngram => {
                if let Some(params) = ngram_params {
                    Box::new(NgramFormatter::new(params))
                } else {
                    Box::new(NgramFormatter::default())
                }
            },
        }
    }
}

/// Parameters for n-gram generation
#[derive(Debug, Clone, Copy)]
pub struct NgramParams {
    /// Size of the n-gram (number of instructions in sequence)
    pub n: usize,
    /// Whether to include operands or just mnemonics
    pub include_operands: bool,
}

impl Default for NgramParams {
    fn default() -> Self {
        Self {
            n: 3,
            include_operands: false,
        }
    }
}

/// Formatter trait for disassembly output
pub trait DisassemblyFormatter {
    /// Format a disassembly result
    fn format(&self, disassembly: &Disassembly, base_addr: Address) -> Result<String, DisassemblyError>;
}

/// Format disassembly in plain text
pub struct TextFormatter;

/// Format disassembly in JSON
pub struct JsonFormatter;

/// Format disassembly in JSON Lines
pub struct JsonLinesFormatter;

/// Format disassembly in CSV
pub struct CsvFormatter;

/// Format disassembly as instruction n-grams
pub struct NgramFormatter {
    params: NgramParams,
}


impl NgramFormatter {
    /// Create a new n-gram formatter with custom parameters
    pub fn new(params: NgramParams) -> Self {
        Self { params }
    }
    
    /// Create a new n-gram formatter with default parameters
    pub fn default() -> Self {
        Self { params: NgramParams::default() }
    }
}

impl DisassemblyFormatter for TextFormatter {
    fn format(&self, disassembly: &Disassembly, base_addr: Address) -> Result<String, DisassemblyError> {
        let mut output = String::new();
        
        match disassembly {
            Disassembly::Stream(insns) => {
                output.push_str(&format!("Disassembly at 0x{:x}:\n\n", base_addr));
                
                for insn in insns {
                    // Format bytes as hex
                    let bytes = insn.bytes()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    
                    output.push_str(&format!("0x{:08x}: {:<10} {:<30} ; {}\n", 
                        insn.addr, insn.mnemonic, insn.operands, bytes));
                }
            },
            Disassembly::Cfg(blocks) => {
                output.push_str(&format!("Control Flow Graph at 0x{:x}:\n\n", base_addr));
                
                for block in blocks {
                    output.push_str(&format!("Block at 0x{:08x}:\n", block.start));
                    
                    for insn in &block.insns {
                        // Format bytes as hex
                        let bytes = insn.bytes()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        
                        output.push_str(&format!("  0x{:08x}: {:<10} {:<30} ; {}\n", 
                            insn.addr, insn.mnemonic, insn.operands, bytes));
                    }
                    
                    // Format successors
                    if block.succs.is_empty() {
                        output.push_str("  No successors (terminal block)\n");
                    } else {
                        output.push_str("  Successors: ");
                        for (i, succ) in block.succs.iter().enumerate() {
                            if i > 0 {
                                output.push_str(", ");
                            }
                            output.push_str(&format!("0x{:08x}", succ));
                        }
                        output.push('\n');
                    }
                    
                    output.push('\n');
                }
            }
        }
        
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Insn, BasicBlock, Disassembly};
    
    fn create_test_instructions() -> Vec<Insn> {
        vec![
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
                size: 1,
                mnemonic: "ret".to_string(),
                operands: "".to_string(),
                bytes: [0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
        ]
    }
    
    fn create_test_blocks() -> Vec<BasicBlock> {
        let block1 = BasicBlock {
            start: 0x1000,
            insns: vec![
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
            ],
            succs: vec![0x1004],
        };
        
        let block2 = BasicBlock {
            start: 0x1004,
            insns: vec![
                Insn {
                    addr: 0x1004,
                    size: 1,
                    mnemonic: "ret".to_string(),
                    operands: "".to_string(),
                    bytes: [0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                },
            ],
            succs: vec![],
        };
        
        vec![block1, block2]
    }
    
    #[test]
    fn test_text_formatter_stream() {
        let disasm = Disassembly::Stream(create_test_instructions());
        let formatter = TextFormatter;
        
        let result = formatter.format(&disasm, 0x1000).unwrap();
        
        // Check that the result contains all instructions
        assert!(result.contains("push"));
        assert!(result.contains("mov"));
        assert!(result.contains("ret"));
        
        // Check formatting
        assert!(result.contains("0x00001000: push"));
        assert!(result.contains("0x00001001: mov"));
        assert!(result.contains("0x00001004: ret"));
    }
    
    #[test]
    fn test_text_formatter_cfg() {
        let disasm = Disassembly::Cfg(create_test_blocks());
        let formatter = TextFormatter;
        
        let result = formatter.format(&disasm, 0x1000).unwrap();
        
        // Check that the result contains all blocks and instructions
        assert!(result.contains("Block at 0x00001000"));
        assert!(result.contains("Block at 0x00001004"));
        assert!(result.contains("push"));
        assert!(result.contains("mov"));
        assert!(result.contains("ret"));
        
        // Check successor formatting
        assert!(result.contains("Successors: 0x00001004"));
        assert!(result.contains("No successors"));
    }
    
    #[test]
    fn test_format_selection() {
        let formats = OutputFormat::available_formats();
        
        // Check that we can create a formatter for each format
        for format in formats {
            let formatter = format.get_formatter(None);
            
            // Just check that it doesn't panic
            let _ = formatter;
        }
    }
}