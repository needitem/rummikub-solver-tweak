from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

program = getCurrentProgram()
fm = program.getFunctionManager()
af = program.getAddressFactory().getDefaultAddressSpace()

ifc = DecompInterface()
ifc.openProgram(program)
monitor = ConsoleTaskMonitor()

targets = [
    (0x290e8b8, "RmkbGameView3D.OnMouseUp"),
    (0x290f7bc, "RmkbGameView3D.FireMoveMadeEvent"),
    (0x290dd88, "RmkbGameView3D.MouseDownOnTile"),
]

for va, name in targets:
    addr = af.getAddress(va)
    func = fm.getFunctionContaining(addr)
    print("=" * 70)
    print("%s @ 0x%x" % (name, va))
    if func is None:
        print("  NO FUNCTION")
        continue
    res = ifc.decompileFunction(func, 120, monitor)
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("  DECOMPILE FAILED: %s" % res.getErrorMessage())

ifc.dispose()
print("DONE")
