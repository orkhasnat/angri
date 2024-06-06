import logging
from typing import Dict, List, NoReturn

import angr
import archinfo
import capstone
import claripy
import monkeyhex  # noqa: F401
from angr import SimState

logging.getLogger("angr").setLevel(logging.ERROR)

return_addr = {}

class SymbolicReturn(angr.SimProcedure):

    def find_call_target(self, call_addr):
        block = self.state.project.factory.block(
            call_addr, size=0x10
        )
        bytes_at_addr = block.bytes

        md = capstone.Cs(
            self.state.project.arch.cs_arch,
            self.state.project.arch.cs_mode,
        )
        md.detail = True

        for instr in md.disasm(bytes_at_addr, call_addr):
            if instr.mnemonic == "call":
                return instr.op_str

        raise ValueError("No call instruction found at the given address")

    def run(self):

        global return_addr
        if self.state.addr not in return_addr:
            return NoReturn
        
        block = self.state.project.factory.block(
            self.state.addr, size=0x10
        )
        bytes_at_addr = block.bytes

        md = capstone.Cs(
            self.state.project.arch.cs_arch,
            self.state.project.arch.cs_mode,
        )
        md.detail = True
        instr = None
        for i in md.disasm(bytes_at_addr, self.state.addr):
            if i.address == self.state.addr:
                instr = i
                break
        # print()
        # print(f"ip: {hex(self.state.addr)}")
        # print(f"nopping: {instr}")
        # print(f"{instr.size} bytes")
        # print()
        self.state.project.loader.memory.store(self.state.addr, self.state.solver.BVV(b'\x90' * instr.size, 8*instr.size))


        # call_target = self.find_call_target(self.state.addr)
        # print(f"ip: {hex(self.state.addr)}")
        # print(f"symbolic function call to {call_target}")
        # symbolic_ret_val = self.state.solver.BVS(
        #     f"ret_val_{call_target}", self.state.arch.bits
        # )
        # # self.ret(symbolic_ret_val)

        # print(f"setting up a symbolic return {symbolic_ret_val}")
        # arch = self.state.arch
        # if isinstance(arch, archinfo.ArchX86):
        #     self.state.regs.eax = symbolic_ret_val
        # elif isinstance(arch, archinfo.ArchAMD64):
        #     self.state.regs.rax = symbolic_ret_val
        # elif isinstance(arch, archinfo.ArchARM):
        #     self.state.regs.r0 = symbolic_ret_val
        # elif isinstance(arch, archinfo.ArchMIPS32):
        #     self.state.regs.v0 = symbolic_ret_val
        # else:
        #     raise NotImplementedError(
        #         f"Return value setting not implemented for architecture: {arch.name}"
        #     )
        # print(f"jumping to return address {hex(return_addr[self.state.addr])}")
        # self.jump(return_addr[self.state.addr])
        return NoReturn


class Binary:
    def __init__(self, binary_path: str):
        self.proj = angr.Project(binary_path, load_options={"auto_load_libs": False})
        self.cfg = self.proj.analyses.CFGFast()
        self.cfg.normalize()
        self.fms = self.cfg.kb.functions
        self.path = []
        self.paths = []
        self.func_paths = {}
        self.str_constrs = set()


    def hook_call_sites(self, call_sites):
        for call_site in call_sites:
            self.proj.hook(call_site, SymbolicReturn())

    def unhook_call_sites(self, call_sites):
        for call_site in call_sites:
            self.proj.unhook(call_site)
        global return_addr
        return_addr = {}

    def get_call_sites(self, function):
        global return_addr
        return_addr = {}
        call_sites = []

        all_instructions = []
        blocks = sorted(function.blocks, key=lambda x: x.addr)

        for block in blocks:
            for insn in block.capstone.insns:
                all_instructions.append(insn)
        ret = all_instructions[-1].address
        for index, insn in enumerate(all_instructions):
            if insn.mnemonic == "ret":
                ret = insn.address
            if insn.mnemonic == "call":
                call_site = insn.address
                call_sites.append(call_site)
                return_addr[call_site] = all_instructions[index + 1].address if index + 1 < len(all_instructions) else ret
        # for call, ret in return_addr.items():
        #     print(f"{hex(call)}:{hex(ret)}")
        return call_sites

    @staticmethod
    def filter(fname: str) -> bool:
        blacklist = [
            "_start",
            "__libc_",
            "__do_global",
            "_ini",
            "_fini",
            "dummy",
            "register_tm_clone",
        ]
        for name in blacklist:
            if name in fname:
                return True
        return False

    @staticmethod
    def is_constant_expr(expr) -> bool:
        return isinstance(expr, claripy.ast.BV) and expr.op == "BVV"

    def expr_handler(self, state: SimState):
        expr_result = state.inspect.expr_result
        # if not self.is_constant_expr(expr_result):
        if str(expr_result) not in self.str_constrs:
            self.path.append(expr_result)
            self.str_constrs.add(str(expr_result))

    def constraints_handler(self, state: SimState):
        added_constraints = state.inspect.added_constraints
        for i in added_constraints:
            if str(i) not in self.str_constrs:
                self.path.append(i)
                self.str_constrs.add(str(i))

    def call_handler(self, state: SimState):
        global return_addr

        if state.addr not in return_addr:
            return

        symbolic_ret_val = state.solver.BVS(
            f"ret_val_{state.inspect.function_address}", state.arch.bits
        )
        print(f"setting up a symbolic return {symbolic_ret_val}")
        arch = state.arch
        if isinstance(arch, archinfo.ArchX86):
            state.regs.eax = symbolic_ret_val
            state.regs.eip = return_addr[state.addr]
        elif isinstance(arch, archinfo.ArchAMD64):
            state.regs.rax = symbolic_ret_val
            state.regs.rip = return_addr[state.addr]
        elif isinstance(arch, archinfo.ArchARM):
            state.regs.r0 = symbolic_ret_val
            state.regs.pc = return_addr[state.addr]
        elif isinstance(arch, archinfo.ArchMIPS32):
            state.regs.v0 = symbolic_ret_val
            state.regs.pc = return_addr[state.addr]
        else:
            raise NotImplementedError(
                f"Return value setting not implemented for architecture: {arch.name}"
            )

    def setup_breakpoints(self, state: SimState):
        state.inspect.b("expr", when=angr.BP_AFTER, action=self.expr_handler)
        # state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_handler)
        state.inspect.b(
            "constraints", when=angr.BP_AFTER, action=self.constraints_handler
        )

    def get_function_paths(self) -> Dict[str, List]:
        for f in self.fms._function_map.values():
            if self.filter(f.name) or f.is_plt or f.is_simprocedure or f.is_alignment or f.is_syscall:
                continue

            # print(f)
            # f.pp()
            call_sites = self.get_call_sites(f)
            self.hook_call_sites(call_sites)

            state = self.proj.factory.blank_state(addr=f.addr)
            state.options.add(angr.options.LAZY_SOLVES)
            state.options.add(angr.options.UNICORN)
            self.setup_breakpoints(state)

            simgr = self.proj.factory.simgr(state)
            dfs_tech = angr.exploration_techniques.DFS()
            simgr.use_technique(dfs_tech)
            loopseer = angr.exploration_techniques.LoopSeer()
            simgr.use_technique(loopseer)

            while simgr.active:
                # try:
                #     block = self.proj.factory.block(addr=state.addr)
                #     block.pp()
                # except:  # noqa: E722
                #     pass
                simgr.step()
                self.paths.append(self.path)
                self.path = []

            self.func_paths[f.name] = self.paths
            # if f.name == "fun1" or f.name == "fun2":
            # print(self.paths)
            self.paths = []
            self.unhook_call_sites(call_sites=call_sites)

        return self.func_paths
