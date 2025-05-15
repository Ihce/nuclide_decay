//! Disassembly strategies

use std::fmt;
use clap::ValueEnum;
use crate::{Decoder, Disassembly, DisassemblyError};

/// Available disassembly strategies.
#[derive(Copy, Clone, ValueEnum, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// Linear sweep disassembly
    Linear,
    /// Superset disassembly (all possible instructions)
    Superset,
    /// Probabilistic disassembly
    Probabilistic,
    /// Recursive descent disassembly (control flow analysis)
    Recursive,
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Strategy::Linear => write!(f, "Linear sweep"),
            Strategy::Superset => write!(f, "Superset"),
            Strategy::Probabilistic => write!(f, "Probabilistic"),
            Strategy::Recursive => write!(f, "Recursive descent"),
        }
    }
}

impl Strategy {
    /// Run the selected strategy on `image` using `decoder`.
    pub fn run(&self, image: &[u8], decoder: &dyn Decoder) -> Result<Disassembly, DisassemblyError> {
        match self {
            Strategy::Linear       => linear::run(image, decoder),
            Strategy::Superset     => superset::run(image, decoder),
            Strategy::Probabilistic=> probabilistic::run(image, decoder),
            Strategy::Recursive    => recursive::run(image, decoder),
        }
    }
    
    /// Return all available strategies
    pub fn all() -> &'static [Strategy] {
        &[
            Strategy::Linear,
            Strategy::Superset,
            Strategy::Probabilistic,
            Strategy::Recursive,
        ]
    }
    
    /// Return the default strategy
    pub fn default() -> Self {
        Strategy::Linear
    }
}

pub mod linear;
pub mod superset;
pub mod probabilistic;
pub mod recursive;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::CapstoneDecoder;
    use crate::Architecture;
    
    #[test]
    fn test_strategy_display() {
        assert_eq!(Strategy::Linear.to_string(), "Linear sweep");
        assert_eq!(Strategy::Recursive.to_string(), "Recursive descent");
    }
    
    #[test]
    fn test_linear_strategy() {
        // Simple x86 code: two instructions
        let bytes = [0x90, 0x90];  // NOP, NOP
        
        let decoder = CapstoneDecoder::for_architecture(Architecture::X86_32).unwrap();
        let result = Strategy::Linear.run(&bytes, &decoder).unwrap();
        
        if let Disassembly::Stream(insns) = result {
            assert_eq!(insns.len(), 2);
            assert_eq!(insns[0].mnemonic, "nop");
            assert_eq!(insns[1].mnemonic, "nop");
        } else {
            panic!("Expected Stream disassembly");
        }
    }
}