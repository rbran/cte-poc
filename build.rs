use std::env;
use std::error::Error;
use std::path::Path;

use capstone::arch::arm::{ArmOperandType, ArmShift};
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use inkwell::attributes::{Attribute, AttributeLoc};
use inkwell::context::Context;

const DISASM: &[u8] = &[
    0x00, 0xbf, //nop
    0x00, 0x48, //ldr r0, [pc, #0]
    0x00, 0xbf, //nop
    0x00, 0x49, //ldr r1, [pc, #0]
    0x00, 0xbf, //nop
    0x00, 0x4A, //ldr r2, [pc, #0]
    0x08, 0x44, //add r0, r1
    0x10, 0x60, //str r0, [r2, #0x0]
];

fn disassembly(file_bc: &str) {
    //create the IR file
    let context = Context::create();
    let module = context.create_module("cpu");
    let builder = context.create_builder();

    //types
    let i32_type = context.i32_type();
    let isize_type = context.i64_type(); //TODO auto detect
    let void_type = context.void_type();

    //get_reg function
    let get_reg_fun = module.add_function(
        "get_reg",
        i32_type.fn_type(&[isize_type.into(), i32_type.into()], false),
        None,
    );
    //set_reg function
    let set_reg_fun = module.add_function(
        "set_reg",
        void_type.fn_type(
            &[isize_type.into(), i32_type.into(), i32_type.into()],
            false,
        ),
        None,
    );
    //load function
    let nop_fun = module.add_function(
        "nop",
        void_type.fn_type(&[isize_type.into()], false),
        None,
    );
    //load function
    let load_fun = module.add_function(
        "load",
        void_type.fn_type(
            &[
                isize_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
            ],
            false,
        ),
        None,
    );
    //store function
    let store_fun = module.add_function(
        "store",
        void_type.fn_type(
            &[
                isize_type.into(),
                i32_type.into(),
                i32_type.into(),
                i32_type.into(),
            ],
            false,
        ),
        None,
    );

    //add function
    let add_fun = module.add_function(
        "add",
        void_type.fn_type(
            &[isize_type.into(), i32_type.into(), i32_type.into()],
            false,
        ),
        None,
    );

    //cpu function
    let cpu_fun_type = void_type.fn_type(&[isize_type.into()], false);
    let cpu_fun = module.add_function(
        "cpu",
        cpu_fun_type,
        None,
    );
    let kind_id = Attribute::get_named_enum_kind_id("alwaysinline");
    let att = context.create_type_attribute(
        kind_id,
        cpu_fun_type.into(),
    );
    cpu_fun.add_attribute(AttributeLoc::Function, att);
    let basic_block = context.append_basic_block(cpu_fun, "entry");
    builder.position_at_end(basic_block);
    //TODO: impl switch to all the addrs
    let emu_ptr = cpu_fun.get_nth_param(0).unwrap().into_int_value();

    //easy reg convert
    let reg = |x| match x {
        66..=68 => x - 66, //r0..r2
        11 => 15,          //pc
        _ => todo!("unknown reg {}", x),
    };

    //disassembly
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        //.syntax(arch::arm::ArchSyntax::NoRegName)
        .detail(true)
        .endian(capstone::Endian::Little)
        .build()
        .expect("Unable to create capstone");

    let instrs = cs.disasm_all(DISASM, 0).unwrap();
    for inst in instrs.as_ref() {
        //update pc before each inst
        let step = i32_type.const_int(inst.bytes().len() as u64, false);
        let pc = builder
            .build_call(
                get_reg_fun,
                &[emu_ptr.into(), i32_type.const_int(15, false).into()],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();
        let pc_new = builder.build_int_add(pc, step.into(), "pc_new");
        builder.build_call(
            set_reg_fun,
            &[
                emu_ptr.into(),
                i32_type.const_int(15, false).into(),
                pc_new.into(),
            ],
            "",
        );
        let detail: InsnDetail = cs.insn_detail(&inst).unwrap();
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();
        match (inst.id().0, ops.as_slice()) {
            //nop
            (63, _) => {
                builder
                    .build_call(nop_fun, &[emu_ptr.into()], "")
                    .try_as_basic_value();
            }
            //ldr
            (
                83,
                &[ArchOperand::ArmOperand(arch::arm::ArmOperand {
                    vector_index: None,
                    subtracted: false,
                    shift: ArmShift::Invalid,
                    op_type: ArmOperandType::Reg(reg1),
                }), ArchOperand::ArmOperand(arch::arm::ArmOperand {
                    vector_index: None,
                    subtracted: false,
                    shift: ArmShift::Invalid,
                    op_type: ArmOperandType::Mem(mem),
                })],
            ) => {
                let reg1 = i32_type.const_int(reg(reg1.0).into(), false);
                let reg2 = i32_type.const_int(reg(mem.base().0).into(), false);
                let offset = i32_type
                    .const_int(mem.disp().unsigned_abs().into(), true);
                builder
                    .build_call(
                        load_fun,
                        &[
                            emu_ptr.into(),
                            reg1.into(),
                            reg2.into(),
                            offset.into(),
                        ],
                        "",
                    )
                    .try_as_basic_value();
            }
            //str
            (
                240,
                &[ArchOperand::ArmOperand(arch::arm::ArmOperand {
                    vector_index: None,
                    subtracted: false,
                    shift: ArmShift::Invalid,
                    op_type: ArmOperandType::Reg(reg1),
                }), ArchOperand::ArmOperand(arch::arm::ArmOperand {
                    vector_index: None,
                    subtracted: false,
                    shift: ArmShift::Invalid,
                    op_type: ArmOperandType::Mem(mem),
                })],
            ) => {
                let reg1 = i32_type.const_int(reg(reg1.0).into(), false);
                let reg2 = i32_type.const_int(reg(mem.base().0).into(), false);
                let offset = i32_type
                    .const_int(mem.disp().unsigned_abs().into(), true);
                builder.build_call(
                    store_fun,
                    &[emu_ptr.into(), reg1.into(), reg2.into(), offset.into()],
                    "",
                );
            }
            //add
            (
                2,
                &[ArchOperand::ArmOperand(arch::arm::ArmOperand {
                    vector_index: None,
                    subtracted: false,
                    shift: ArmShift::Invalid,
                    op_type: ArmOperandType::Reg(reg1),
                }), ArchOperand::ArmOperand(arch::arm::ArmOperand {
                    vector_index: None,
                    subtracted: false,
                    shift: ArmShift::Invalid,
                    op_type: ArmOperandType::Reg(reg2),
                })],
            ) => {
                let reg1 = i32_type.const_int(reg(reg1.0).into(), false);
                let reg2 = i32_type.const_int(reg(reg2.0).into(), false);
                builder.build_call(
                    add_fun,
                    &[emu_ptr.into(), reg1.into(), reg2.into()],
                    "",
                );
            }
            _ => todo!(),
        }
    }
    builder.build_return(None);

    module.write_bitcode_to_path(Path::new(&file_bc));
}

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let filename = "emu";
    let file_bc = format!("{}/{}.{}", out_dir, filename, "bc");

    disassembly(&file_bc);

    //compile emu
    cc::Build::new()
        .file(&file_bc)
        //TODO: complete clang path
        .compiler("clang")
        //.opt_level(3)
        //TODO: this is a semi-fix for emu.bc having the wrong target
        .flag("-Wno-override-module")
        .flag("-flto=thin")
        .compile(&filename);

    //compile with link time optimizations
    //println!(
    //    "cargo:rustc-flags={}",
    //    "-Clinker-plugin-lto -Clinker=clang -Clink-arg=-fuse-ld=lld"
    //);
    println!("cargo:rustc-link-search={}", out_dir);
    println!("cargo:rustc-link-lib={}", filename);

    Ok(())
}
