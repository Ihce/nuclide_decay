//! Probabilistic disassembly strategy
//!
//! This is a pure-Rust port of Kenneth Miller's probabilistic disassembly approach.
//! It first runs superset disassembly, then builds a graph structure from the results,
//! and finally applies heuristic voting with propagation to classify code vs. data.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;
use rayon::prelude::*;
use crate::{Address, Decoder, Disassembly, DisassemblyError, Insn};

// === Implementation ===

#[derive(Debug, Clone)]
pub struct Entry {
    pub offset: usize,
    pub size: u8,
    pub opcode: u8,
    pub mnemonic: String,
    pub successors: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Code,
    Data,
}

pub type ResultMap = HashMap<usize, State>;
pub type Heuristic = fn(&Entry) -> bool;

pub struct ProbDisassembler {
    pub heurisms: &'static [Heuristic],
    pub keep_threshold: i32,
}

impl ProbDisassembler {
    pub fn new() -> Self {
        Self {
            heurisms: DEFAULTS,
            keep_threshold: 1,
        }
    }

    pub fn classify(&self, entries: &[Entry], entry_map: &HashMap<usize, usize>) -> ResultMap {
        let mut score: HashMap<usize, i32> = HashMap::new();
        for &h in self.heurisms {
            for e in entries {
                if h(e) {
                    *score.entry(e.offset).or_default() += 1;
                }
            }
        }
        let propagated = self.propagate_votes(entries, entry_map, score);
        propagated
            .into_iter()
            .map(|(off, s)| {
                let st = if s >= self.keep_threshold {
                    State::Code
                } else {
                    State::Data
                };
                (off, st)
            })
            .collect()
    }

    fn propagate_votes(&self, entries: &[Entry], entry_map: &HashMap<usize, usize>, initial: HashMap<usize, i32>) -> HashMap<usize, i32> {
        let mut votes = initial;
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 5 {
            changed = false;
            iterations += 1;
            let prev_votes = votes.clone();
            for entry in entries {
                let cur_votes = *prev_votes.get(&entry.offset).unwrap_or(&0);
                for &succ in &entry.successors {
                    if entry_map.contains_key(&succ) {
                        let succ_votes = votes.entry(succ).or_insert(0);
                        let propagated = (cur_votes as f32 * 0.5).floor() as i32;
                        if propagated > 0 {
                            let old = *succ_votes;
                            *succ_votes = (*succ_votes).max(propagated);
                            if *succ_votes != old {
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        votes
    }
}

pub fn run(image: &[u8], decoder: &dyn Decoder) -> Result<Disassembly, DisassemblyError> {
    let mut entries = Vec::with_capacity(image.len() / 8);
    let batch_size = 4096;
    let batch_count = (image.len() + batch_size - 1) / batch_size;
    for batch_idx in 0..batch_count {
        let start = batch_idx * batch_size;
        let end = std::cmp::min(start + batch_size, image.len());
        let batch_entries: Vec<Entry> = (start..end)
            .into_par_iter()
            .filter_map(|offset| decoder.decode(image, offset as u64).map(|i| insn_to_entry(image, &i)))
            .collect();
        entries.extend(batch_entries);
    }
    let entry_map = build_graph(image, &mut entries);
    let pd = ProbDisassembler::new();
    let mut classified = pd.classify(&entries, &entry_map);
    trim_unreachable(&entries, &mut classified);
    let liveness = compute_liveness(&entries);
    for e in &entries {
        let inv = analyze_invariants(e);
        let live = liveness.get(&e.offset);
        println!("0x{:x}: {:?} → {:?}", e.offset, inv, live);
    }
    let mut kept = Vec::new();
    for (offset, state) in classified {
        if state == State::Code {
            if let Some(insn) = decoder.decode(image, offset as u64) {
                kept.push(insn);
            }
        }
    }
    kept.sort_by_key(|i| i.addr);
    Ok(Disassembly::Stream(kept))
}

pub fn insn_to_entry(image: &[u8], i: &Insn) -> Entry {
    Entry {
        offset: i.addr as usize,
        size: i.size as u8,
        opcode: image[i.addr as usize],
        mnemonic: i.mnemonic.clone(),
        successors: Vec::new(),
    }
}

pub fn build_graph(image: &[u8], entries: &mut Vec<Entry>) -> HashMap<usize, usize> {
    let mut map = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        map.insert(e.offset, i);
    }
    entries.sort_by_key(|e| e.offset);
    for (i, e) in entries.iter().enumerate() {
        map.insert(e.offset, i);
    }
    for i in 0..entries.len() {
        let e = &entries[i];
        let mut succ = Vec::new();
        if !is_ret(e) {
            let next = e.offset + e.size as usize;
            if map.contains_key(&next) {
                succ.push(next);
            }
        }
        entries[i].successors = succ;
    }
    map
}

pub fn img_entry(e: &Entry) -> bool { e.offset == 0 }
pub fn branch_violation(e: &Entry) -> bool { matches!(e.opcode, 0xE9 | 0xEB) }
pub fn call_site(e: &Entry) -> bool { e.mnemonic == "call" }
pub fn fanout_gt1(e: &Entry) -> bool { e.successors.len() > 1 }
pub fn is_ret(e: &Entry) -> bool { matches!(e.opcode, 0xC3 | 0xC2 | 0xCB | 0xCA) }
pub fn align_nop(e: &Entry) -> bool { e.opcode == 0x90 && (e.offset & 0xF) == 0 && e.size == 1 }
pub fn tiny_instr(e: &Entry) -> bool { e.size < 3 }
pub fn leaf_block(e: &Entry) -> bool { is_ret(e) && e.successors.is_empty() }
pub fn not_indirect(e: &Entry) -> bool { !matches!(e.opcode, 0xFF | 0xEA) }
pub fn default_vote(_: &Entry) -> bool { true }

pub const DEFAULTS: &[fn(&Entry) -> bool] = &[
    img_entry,
    branch_violation,
    call_site,
    fanout_gt1,
    is_ret,
    align_nop,
    tiny_instr,
    leaf_block,
    not_indirect,
    default_vote,
];

#[derive(Default, Debug)]
pub struct Invariants {
    pub sp_delta: i32,
    pub known_consts: HashMap<String, i64>,
}

pub fn analyze_invariants(entry: &Entry) -> Invariants {
    let mut inv = Invariants::default();
    if entry.mnemonic == "push" {
        inv.sp_delta -= entry.size as i32;
    } else if entry.mnemonic == "pop" {
        inv.sp_delta += entry.size as i32;
    }
    if entry.mnemonic == "mov" && entry.successors.is_empty() && entry.opcode == 0xb8 {
        inv.known_consts.insert("rax".to_string(), 0);
    }
    inv
}

#[derive(Debug, Default, Clone)]
pub struct Liveness {
    pub live_in: HashSet<String>,
    pub live_out: HashSet<String>,
}

pub fn compute_liveness(entries: &[Entry]) -> HashMap<usize, Liveness> {
    let mut result = HashMap::new();
    for entry in entries.iter().rev() {
        let mut live: Liveness = result.get(&entry.offset).cloned().unwrap_or_default();
        if entry.mnemonic != "mov" {
            live.live_out.extend(["rax", "rbx", "rcx", "rdx"].iter().map(|s| s.to_string()));
        }
        result.insert(entry.offset, live);
    }
    result
}

pub fn trim_unreachable(entries: &[Entry], state: &mut ResultMap) {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for e in entries {
        if let Some(State::Code) = state.get(&e.offset) {
            if e.mnemonic == "call" || e.mnemonic == "jmp" || e.mnemonic == "ret" {
                queue.push_back(e.offset);
                visited.insert(e.offset);
            }
        }
    }
    while let Some(current) = queue.pop_front() {
        if let Some(entry) = entries.iter().find(|e| e.offset == current) {
            for &succ in &entry.successors {
                if state.get(&succ) == Some(&State::Code) && visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
    for (&offset, tag) in state.iter_mut() {
        if *tag == State::Code && !visited.contains(&offset) {
            *tag = State::Data;
        }
    }
}

// === Tests ===
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::CapstoneDecoder;
    use crate::Architecture;

    #[test]
    fn test_probabilistic_disassembly() {
        let bytes = [
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3,                         // ret
            0xFF, 0xFF, 0xFF, 0xFF,       // junk
            0x90,                         // nop
            0xC3                          // ret
        ];

        let decoder = CapstoneDecoder::for_architecture(Architecture::X86_32).unwrap();
        let superset_insns: Vec<Insn> = (0..bytes.len())
            .filter_map(|offset| decoder.decode(&bytes, offset as u64))
            .collect();

        let result = run(&bytes, &decoder).unwrap();
        if let Disassembly::Stream(insns) = result {
            assert!(insns.iter().any(|i| i.addr == 0 && i.mnemonic == "mov"));
            assert!(insns.iter().any(|i| i.addr == 5 && i.mnemonic == "ret"));
            println!("Superset found {} instructions", superset_insns.len());
            println!("Probabilistic kept {} instructions", insns.len());
            for i in &insns {
                println!("0x{:x}: {} {}", i.addr, i.mnemonic, i.operands);
            }
        } else {
            panic!("Expected Stream disassembly");
        }
    }

    #[test]
    fn test_basic_probabilistic_disassembly() {
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let decoder = CapstoneDecoder::for_architecture(Architecture::X86_32).unwrap();
        let result = run(&bytes, &decoder).unwrap();

        if let Disassembly::Stream(insns) = result {
            assert!(insns.iter().any(|i| i.addr == 0 && i.mnemonic == "mov"));
            assert!(insns.iter().any(|i| i.addr == 5 && i.mnemonic == "ret"));
        } else {
            panic!("Expected Stream disassembly");
        }
    }
}
