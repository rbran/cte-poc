const MEM_SIZE: u32 = 32 * 4;
struct Emu {
    reg: [u32; 16],
    mem: [u8; MEM_SIZE as usize],
}

extern "C" {
    fn cpu(emu: usize) -> u32;
}
fn cpu_wrap(emu: &mut Emu) -> u32 {
    unsafe {
        let emu = core::mem::transmute::<&mut Emu, usize>(emu);
        cpu(emu)
    }
}

impl Default for Emu {
    fn default() -> Self {
        Emu {
            reg: [0; 16],
            mem: [0; MEM_SIZE as usize],
        }
    }
}

macro_rules! debug {
    ($($e:expr),+) => {
        {
            #[cfg(debug_assertions)]
            {
                println!($($e),+)
            }
            #[cfg(not(debug_assertions))]
            {
                ($($e),+)
            }
        }
    };
}

#[inline(always)]
#[no_mangle]
fn get_reg(emu: usize, reg: u32) -> u32 {
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    let value = emu.reg[reg as usize];
    debug!("get_reg(reg: {}) => {}", reg, value);
    value
}
#[inline(always)]
#[no_mangle]
fn set_reg(emu: usize, reg: u32, value: u32) {
    debug!("set_reg(reg: {}, value: {})", reg, value);
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    emu.reg[reg as usize] = value;
}

#[inline(always)]
#[no_mangle]
fn nop(emu: usize) {
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    emu.reg[15] += 2; //update pc
    debug!("nop()");
}
#[inline(always)]
fn read_mem(emu: &Emu, addr: usize) -> u32 {
    u32::from_le_bytes(emu.mem[addr..addr + 4].try_into().unwrap())
}
#[inline(always)]
fn write_mem(emu: &mut Emu, addr: usize, value: u32) {
    emu.mem[addr..addr + 4].copy_from_slice(&value.to_le_bytes());
}
#[inline(always)]
#[no_mangle]
fn load(emu: usize, reg1: u32, reg2: u32, offset: u32) {
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    emu.reg[15] += 2; //update pc
    let addr = (emu.reg[reg2 as usize] + offset) as usize;
    let value = read_mem(emu, addr);
    debug!(
        "load(reg1: {}, reg2: {}, offset: {}); value = {}",
        reg1, reg2, offset, value
    );
    emu.reg[reg1 as usize] = value;
}
#[inline(always)]
#[no_mangle]
fn store(emu: usize, reg1: u32, reg2: u32, offset: u32) {
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    emu.reg[15] += 2; //update pc
    let addr = (emu.reg[reg2 as usize] + offset) as usize;
    let value = emu.reg[reg1 as usize];
    debug!(
        "store(reg1: {}, reg2: {}, offset: {}); value = {}",
        reg1, reg2, offset, value
    );
    write_mem(emu, addr, value);
}

#[inline(always)]
#[no_mangle]
fn add(emu: usize, reg1: u32, reg2: u32) {
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    emu.reg[15] += 2; //update pc
    emu.reg[reg1 as usize] += emu.reg[reg2 as usize];
    debug!(
        "add(reg1: {}, reg2: {}); res = {}",
        reg1, reg2, emu.reg[reg1 as usize]
    );
}

#[inline(always)]
#[no_mangle]
fn bx(emu: usize, reg: u32) {
    let emu = unsafe { core::mem::transmute::<usize, &mut Emu>(emu) };
    emu.reg[15] = emu.reg[reg as usize]; //update pc
    debug!("bx(reg: {}); value = {}", reg, emu.reg[reg as usize]);
}

fn main() {
    //emu is:
    //let (r0, r1, r2, r3) = (mem[4], mem[8], mem[12], mem[16]);
    //r0 += r1;
    //goto r3;
    //mem[r2] = r0;
    let mut emu = Emu::default();
    write_mem(&mut emu, 4, 5);     //r0
    write_mem(&mut emu, 8, 37);    //r1
    write_mem(&mut emu, 12, 20);   //r2
    write_mem(&mut emu, 16, 0x12); //r3 = addr 0x12
    println!("CPU: {}", cpu_wrap(&mut emu));
    println!("r0 = {}", emu.reg[0]);
    println!("result on RAM = {}", read_mem(&mut emu, 20));
}
