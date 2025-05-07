// ------------------------------------------------------------------
// Shared IR & traits for *all* disassembly strategies.
// Some strategies (linear‑sweep, superset) only emit a flat instruction
// stream, while others (recursive descent) build a control‑flow graph.
// Therefore `Disassembly` is now an **enum** with two variants.
// ------------------------------------------------------------------

/// 64‑bit offset into the raw image (we treat “address” == “file offset”).
pub type Address = u64;

/*───────────────────────────────────────────────────────────────────────────
 *  Instruction
 *─────────────────────────────────────────────────────────────────────────*/

/// One decoded instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: Address,          // absolute offset in the binary blob
    pub size: u8,               // length in bytes
    pub mnemonic: &'static str, // static str to avoid allocations in hot loops
    pub bytes: [u8; 16],        // first 16 bytes (x86 max), 0‑padded
}

/*───────────────────────────────────────────────────────────────────────────
 *  Decoder abstraction
 *─────────────────────────────────────────────────────────────────────────*/

/// Architecture‑specific decoder (Capstone, iced‑x86, LLVM MC, …).
/// Implementors must be `Send + Sync` so callers can decode in parallel.
pub trait Decoder: Send + Sync {
    /// Decode ONE instruction at `at` (file offset). Returns `None` if bytes
    /// don’t form a valid instruction for this ISA.
    fn decode(&self, image: &[u8], at: Address) -> Option<Insn>;
}

/*───────────────────────────────────────────────────────────────────────────
 *  CFG structs (used by graph‑building strategies)
 *─────────────────────────────────────────────────────────────────────────*/

/// One basic block: a linear sequence of instructions terminated by a branch.
#[derive(Debug)]
pub struct BasicBlock {
    pub start: Address,
    pub insns: Vec<Insn>,
    pub succs: Vec<Address>, // successor block starts (fall‑through, jump)
}

/*───────────────────────────────────────────────────────────────────────────
 *  Unified output enum
 *─────────────────────────────────────────────────────────────────────────*/

#[derive(Debug)]
pub enum Disassembly {
    /// Flat list of every accepted instruction (linear sweep, superset…).
    Stream(Vec<Insn>),

    /// Control‑flow graph produced by recursive descent, etc.
    Cfg(Vec<BasicBlock>),
}

/*───────────────────────────────────────────────────────────────────────────
 *  Strategy abstraction
 *─────────────────────────────────────────────────────────────────────────*/

/// Every disassembly algorithm implements `Strategy`, so callers can pick
/// at runtime without caring whether it builds a CFG or just a stream.
pub trait Strategy: Send + Sync {
    /// Short human‑readable name (for CLI listing / logs).
    fn name(&self) -> &'static str;

    /// Perform disassembly using architecture decoder `D`.
    fn run_disassembly<D: Decoder>(&self, image: &[u8], decoder: &D) -> Disassembly;
}
