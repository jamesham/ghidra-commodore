package commodore;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProgramProcessorContext;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

public class CommodoreUtils {

	public static long createJumpVector(String symbolName, Address symbolAddr, Namespace namespace, SymbolTable symbolTable, Program program, MessageLog log) throws InvalidInputException {
		long vectorAddr = -1;		

		symbolTable.createLabel(symbolAddr, symbolName+"_JMP", namespace, SourceType.IMPORTED); //$NON-NLS-1$
		
		try {
			MemBuffer buf = new DumbMemBufferImpl(program.getMemory(), symbolAddr);
			ProcessorContext context = new ProgramProcessorContext(program.getProgramContext(), symbolAddr);
			InstructionPrototype proto = program.getLanguage().parse(buf, context, false);
			Instruction inst = program.getListing().createInstruction(symbolAddr, proto, buf, context);
						
			if (inst.getFlowType().isJump()) {
				Address[] jumpTargets = inst.getDefaultFlows();
				if (jumpTargets.length == 1) {
					Address functionAddr = jumpTargets[0];
					symbolTable.createLabel(functionAddr, symbolName, namespace, SourceType.IMPORTED); //$NON-NLS-1$
					symbolTable.addExternalEntryPoint(functionAddr);
				}
			}
			
		} catch (CodeUnitInsertionException | InsufficientBytesException | UnknownInstructionException e) {
			throw new InvalidInputException(e.getMessage());
		}
		
		return vectorAddr;
	}
	
	public static long createVectorAddress(String symbolName, Address symbolAddr, Namespace namespace, SymbolTable symbolTable, Program program, MessageLog log) throws InvalidInputException {
		long vectorAddr = -1;
		
		symbolTable.createLabel(symbolAddr, symbolName+"_VECTOR", namespace, SourceType.IMPORTED); //$NON-NLS-1$
		
		try {
			Data ptr = program.getListing().createData(symbolAddr, new PointerDataType());
			Class<?> cl = ptr.getValueClass();
			if (Address.class.isAssignableFrom(cl)) {
				Address ptrAddr = (Address) ptr.getValue();
				symbolTable.createLabel(ptrAddr, symbolName, namespace, SourceType.IMPORTED);
				symbolTable.addExternalEntryPoint(ptrAddr);
				vectorAddr = ptrAddr.getAddressableWordOffset();
			} else {
				log.appendMsg(String.format("Failed to get pointer from value %s at 0x%04x (Found class: %s - Expected %s)", symbolName, symbolAddr, cl.getCanonicalName(), Address.class.getCanonicalName()));
			}
		} catch (CodeUnitInsertionException | DataTypeConflictException e) {
			log.appendMsg(String.format("Error creating data pointer \"%s\" (0x%04x): %s", symbolName, symbolAddr, e.getMessage()));
		}
		
		return vectorAddr;
	}

	
}
