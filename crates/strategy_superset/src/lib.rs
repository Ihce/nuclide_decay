// strategy-superset/src/lib.rs
// --------------------------------------------------------------
// Dense “every-offset” scanner a la *superset disassembly*.
// Keeps the **naming scheme** consistent with your historical code base:
// every `Strategy` now exposes `run_disassembly()` (not plain `run`).
// --------------------------------------------------------------

use decay_core::{Address, BasicBlock, Decoder, Disassembly, Insn, Strategy};
use rayon::prelude::*;

pub struct Superset;

impl Strategy for Superset {
    fn name(&self) -> &'static str {
        "superset"
    }

    fn run_disassembly<D: Decoder>(&self, img: &[u8], dec: &D) -> Disassembly {
        let insns = superset_disassemble(img, dec);
        let block = BasicBlock {
            start: 0,
            insns,
            succs: Vec::new(),
        };
        Disassembly::Stream(vec![Insn {
            addr: 0,
            size: 0,
            mnemonic: "",
            bytes: [0; 16],
        }])
    }
}

/// Factory so the registry can create an instance quickly.
pub fn make() -> Superset {
    Superset
}

/*─────────────────────────────────────────────────────────────────*
 *  Helper: dense scan (no gaps, no CFG)
 *─────────────────────────────────────────────────────────────────*/
fn superset_disassemble<D: Decoder>(img: &[u8], dec: &D) -> Vec<Insn> {
    (0..img.len() as Address)
        .into_par_iter()
        .filter_map(|off| dec.decode(img, off))
        .collect()
}

/*─────────────────────────────────────────────────────────────────*
 *  Optional: formatter + error modules (paste your old impls here)
 *─────────────────────────────────────────────────────────────────*/
