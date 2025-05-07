//! Multi-ISA Capstone decoders implementing `decay_core::Decoder`.

use capstone::{Arch, Capstone, Endian, Mode, NO_EXTRA_MODE};
use decay_core::{Address, Decoder, Insn};

/// Build a configured `Capstone` handle.
fn cs(arch: Arch, mode: Mode) -> Capstone {
    Capstone::new()
        .arch(arch)
        .mode(mode)
        .endian(Endian::Little) // change for big-endian MIPS/PPC if needed
        .extra_mode(NO_EXTRA_MODE)
        .detail(false)
        .build()
        .expect("capstone build failed")
}

/*────────────────────────  concrete structs  ───────────────────────*/

macro_rules! mk_decoder {
    ($name:ident, $arch:expr, $mode:expr) => {
        pub struct $name {
            cs: Capstone,
        }
        impl $name {
            pub fn new() -> Self {
                Self {
                    cs: cs($arch, $mode),
                }
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl Decoder for $name {
            fn decode(&self, img: &[u8], at: Address) -> Option<Insn> {
                if at as usize >= img.len() {
                    return None;
                }
                let insn = self
                    .cs
                    .disasm_count(&img[at as usize..], at, 1)
                    .ok()?
                    .iter()
                    .next()?;
                let mut buf = [0u8; 16]; // copy bytes
                let bytes = insn.bytes();
                buf[..bytes.len()].copy_from_slice(bytes);

                let m = insn.mnemonic().unwrap_or("");
                Some(Insn {
                    addr: at,
                    size: bytes.len() as u8,
                    mnemonic: Box::leak(m.to_owned().into_boxed_str()),
                    bytes: buf,
                })
            }
        }
    };
}

mk_decoder!(X86_32, Arch::X86, Mode::Mode32);
mk_decoder!(X86_64, Arch::X86, Mode::Mode64);
mk_decoder!(ARMv7, Arch::ARM, Mode::Arm);
mk_decoder!(Thumb2, Arch::ARM, Mode::Thumb);
mk_decoder!(AArch64, Arch::ARM64, Mode::Arm);
mk_decoder!(Mips32, Arch::Mips, Mode::Mips32);
mk_decoder!(RiscV32, Arch::RiscV, Mode::RiscV32);
mk_decoder!(RiscV64, Arch::RiscV, Mode::RiscV64);
mk_decoder!(Ppc32, Arch::Ppc, Mode::Ppc32);

/*────────────────────────  convenient enum  ───────────────────────*/

/// The nine decoders behind one enum so callers can switch by string/flag.
pub enum Multi {
    X8632(X86_32),
    X86_64(X86_64),
    Arm(ARMv7),
    Thumb(Thumb2),
    AArch64(AArch64),
    Mips32(Mips32),
    Rv32(RiscV32),
    Rv64(RiscV64),
    Ppc32(Ppc32),
}

impl Multi {
    /// Factory by short name (`"x86"`, `"thumb"`, `"riscv64"`, …)
    pub fn by_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "x86" | "i386" => Self::X8632(X86_32::new()),
            "x86_64" | "amd64" => Self::X86_64(X86_64::new()),
            "arm" | "armv7" => Self::Arm(ARMv7::new()),
            "thumb" | "armv7t" => Self::Thumb(Thumb2::new()),
            "aarch64" => Self::AArch64(AArch64::new()),
            "mips32" => Self::Mips32(Mips32::new()),
            "riscv32" => Self::Rv32(RiscV32::new()),
            "riscv64" => Self::Rv64(RiscV64::new()),
            "ppc32" | "powerpc" => Self::Ppc32(Ppc32::new()),
            _ => return None,
        })
    }
}

impl Decoder for Multi {
    fn decode(&self, img: &[u8], at: Address) -> Option<Insn> {
        match self {
            Self::X8632(d) => d.decode(img, at),
            Self::X86_64(d) => d.decode(img, at),
            Self::Arm(d) => d.decode(img, at),
            Self::Thumb(d) => d.decode(img, at),
            Self::AArch64(d) => d.decode(img, at),
            Self::Mips32(d) => d.decode(img, at),
            Self::Rv32(d) => d.decode(img, at),
            Self::Rv64(d) => d.decode(img, at),
            Self::Ppc32(d) => d.decode(img, at),
        }
    }
}
