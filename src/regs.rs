use nix::libc::user_regs_struct;

#[derive(Debug, Clone)]
pub struct Regs {
    pub original: user_regs_struct,
    pub regs: [u64; 6],
    pub syscall_id: u64,
    pub return_value: u64,
}

#[cfg(target_arch = "x86_64")]
impl Regs {
    pub fn default() -> Self {
        Self {
            original: user_regs_struct {
                r15: 0,
                r14: 0,
                r13: 0,
                r12: 0,
                rbp: 0,
                rbx: 0,
                r11: 0,
                r10: 0,
                r9: 0,
                r8: 0,
                rax: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                orig_rax: 0,
                rip: 0,
                cs: 0,
                eflags: 0,
                rsp: 0,
                ss: 0,
                fs_base: 0,
                gs_base: 0,
                ds: 0,
                es: 0,
                fs: 0,
                gs: 0,
            },
            regs: [0; 6],
            syscall_id: 0,
            return_value: 0,
        }
    }

    pub fn from_regs(rr: &user_regs_struct) -> Self {
        Self {
            original: rr.clone(),
            regs: [rr.rdi, rr.rsi, rr.rdx, rr.r10, rr.r8, rr.r9],
            syscall_id: rr.orig_rax,
            return_value: rr.rax,
        }
    }

    pub fn to_regs(&self) -> user_regs_struct {
        user_regs_struct {
            orig_rax: self.syscall_id,
            rdi: self.regs[0],
            rsi: self.regs[1],
            rdx: self.regs[2],
            r10: self.regs[3],
            r8: self.regs[4],
            r9: self.regs[5],
            rax: self.return_value,
            ..self.original
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Regs {
    pub fn default() -> Self {
        Self {
            original: user_regs_struct {
                regs: [0; 31],
                sp: 0,
                pc: 0,
                pstate: 0,
            },
            regs: [0; 6],
            syscall_id: 0,
            return_value: 0,
        }
    }

    pub fn from_regs(rr: &user_regs_struct) -> Self {
        Self {
            original: rr.clone(),
            regs: [
                rr.regs[0], rr.regs[1], rr.regs[2], rr.regs[3], rr.regs[4], rr.regs[5],
            ],
            syscall_id: rr.regs[8],
            return_value: rr.regs[0],
        }
    }

    pub fn to_regs(&self) -> user_regs_struct {
        let regs = [
            self.return_value,
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4],
            self.regs[5],
            self.original.regs[6],
            self.original.regs[7],
            self.syscall_id,
            self.original.regs[9],
            self.original.regs[10],
            self.original.regs[11],
            self.original.regs[12],
            self.original.regs[13],
            self.original.regs[14],
            self.original.regs[15],
            self.original.regs[16],
            self.original.regs[17],
            self.original.regs[18],
            self.original.regs[19],
            self.original.regs[20],
            self.original.regs[21],
            self.original.regs[22],
            self.original.regs[23],
            self.original.regs[24],
            self.original.regs[25],
            self.original.regs[26],
            self.original.regs[27],
            self.original.regs[28],
            self.original.regs[29],
            self.original.regs[30],
        ];
        user_regs_struct {
            regs: regs,
            sp: self.original.sp,
            pc: self.original.pc,
            pstate: self.original.pstate,
        }
    }
}
