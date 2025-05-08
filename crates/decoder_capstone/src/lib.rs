use capstone::{arch::BuildsCapstone, Capstone};
use decay_core::{Address, Decoder, Insn};

/*──────────────────────── helpers ───────────────────────*/

fn build_x86_32() -> Capstone {
    Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode32)
        .build()
        .unwrap()
}
fn build_x86_64() -> Capstone {
    Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
        .build()
        .unwrap()
}
fn build_armv7() -> Capstone {
    Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Arm)
        .build()
        .unwrap()
}
fn build_thumb() -> Capstone {
    Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Thumb)
        .build()
        .unwrap()
}
fn build_aarch64() -> Capstone {
    Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .build()
        .unwrap()
}
fn build_mips32() -> Capstone {
    Capstone::new()
        .mips()
        .mode(capstone::arch::mips::ArchMode::Mips32)
        .build()
        .unwrap()
}
fn build_riscv32() -> Capstone {
    Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV32)
        .build()
        .unwrap()
}
fn build_riscv64() -> Capstone {
    Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV64)
        .build()
        .unwrap()
}
fn build_ppc32() -> Capstone {
    Capstone::new()
        .ppc()
        .mode(capstone::arch::ppc::ArchMode::Mode32)
        .build()
        .unwrap()
}

/*──────────────────────── macro ───────────────────────*/

macro_rules! mk_decoder {
    ($name:ident, $builder:expr) => {
        pub struct $name {
            cs: Capstone,
        }
        impl $name {
            pub fn new() -> Self {
                Self { cs: $builder() }
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
                let disasm = self.cs.disasm_count(&img[at as usize..], at, 1).ok()?;
                let insn = disasm.iter().next()?;
                Some(Insn {
                    addr: insn.address(),
                    size: insn.bytes().len() as u8,
                    bytes: {
                        let mut arr = [0u8; 16];
                        let len = insn.bytes().len().min(16);
                        arr[..len].copy_from_slice(&insn.bytes()[..len]);
                        arr
                    },
                    mnemonic: insn.mnemonic().unwrap_or("").to_string().leak(),
                })
            }
        }
        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}
    };
}

/*──────────────────────── concrete structs ───────────────────────*/

mk_decoder!(X86_32, build_x86_32);
mk_decoder!(X86_64, build_x86_64);
mk_decoder!(ARMv7, build_armv7);
mk_decoder!(Thumb2, build_thumb);
mk_decoder!(AArch64, build_aarch64);
mk_decoder!(Mips32, build_mips32);
mk_decoder!(RiscV32, build_riscv32);
mk_decoder!(RiscV64, build_riscv64);
mk_decoder!(Ppc32, build_ppc32);

/*──────────────────────── enum façade ───────────────────────*/

pub enum Multi {
    X86_32(X86_32),
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
    pub fn by_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "x86" | "i386" => Self::X86_32(X86_32::new()),
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
            Self::X86_32(d) => d.decode(img, at),
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
