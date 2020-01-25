package os9;

import java.util.ArrayList;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class OS9SyscallAnalyzer extends AbstractAnalyzer {
	protected OS9SyscallInfo syscallInfo;
	
	public OS9SyscallAnalyzer() {
		super("OS9 System Call Analyzer", "Recognizes and annotates OS-9 system calls (trap 0 followed by 16 bit function code)", AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY);
		syscallInfo = new OS9SyscallInfo();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// TODO: probably need to check more/different things
		if (program.getExecutableFormat().equals(OS9Loader.LOADER_NAME)) {
			return true;
		}

		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		var syscallInstructions = new ArrayList<Instruction>();
		
		// locate syscall trap instructions
		var listing = program.getListing();
		
		for (var instr: listing.getInstructions(set, true)) {
			monitor.checkCanceled();
			
			if (isSyscall(instr)) {
				syscallInstructions.add(instr);
				instr.setFallThrough(instr.getDefaultFallThrough().add(2));
			}
		}
		
		if (syscallInstructions.isEmpty()) {
			// docs say the return value means 'succeeded'. not sure if that's 'did anything' or 'without errors' -- assuming the latter
			return true;
		}
		
		for (var instr : syscallInstructions) {
			// mark the system call as such
			
			var functionCodeAddr = instr.getDefaultFallThrough();
			
			if (instr.getComment(CodeUnit.PLATE_COMMENT) != null) {
				// don't overwrite existing comments 
				continue;
			}
			
			// try to obtain syscall information from the function code
			OS9Syscall syscall = null;
			try {
				int functionCodeValue = program.getMemory().getShort(functionCodeAddr);
				syscall = syscallInfo.get(functionCodeValue);
				
			} catch (Exception e) {
				log.appendException(e);
			}
			
			String[] comments;
			if (syscall != null) {
				comments = new String[] {
					"OS-9 system call",
					syscall.name,
					syscall.description,
				};					
			} else {
				comments = new String[] {
					"OS-9 system call",
					"Unknown function code",
				};
			}
			
			instr.setCommentAsArray(CodeUnit.PLATE_COMMENT, comments);
		}
		
		Msg.debug(this, "Found " + syscallInstructions.size() + " syscall instructions.");
		
		// syscall traps are followed by a 16-bit function code.
		// find out if the found syscalls have these set up correctly
		var toTag = new AddressSet();
		
		for (var instr : syscallInstructions) {
			monitor.checkCanceled();
			
			var functionCodeAddr = instr.getDefaultFallThrough();
			var codeUnit = listing.getCodeUnitContaining(functionCodeAddr);
			
			if (! isCorrectFunctionCode(codeUnit, instr)) {
				toTag.add(functionCodeAddr);	
				continue;
			}
			
			var nextInstruction = listing.getInstructionAt(instr.getFallThrough());
			if (nextInstruction == null) {
				toTag.add(functionCodeAddr);
			}
		}
		
		Msg.debug(this, "Found " + toTag.getNumAddresses() + " addresses that need (re-)tagging.");
		
		// clear/repair program flow to account for the incorrect function code
		if (! toTag.isEmpty()) {
			var clearCmd = new ClearFlowAndRepairCmd(toTag, true, true, true);
			clearCmd.applyTo(program, monitor);
		
			// tag the function code as a data word
			for (var functionCodeAddr: toTag.getAddresses(true)) {
				monitor.checkCanceled();
				
				try {
					listing.createData(functionCodeAddr, new WordDataType());
				} catch (Exception e) {
					log.appendException(e);
				}
			}
		}

		return true;
	}
	
	protected boolean isSyscall(Instruction instr) {
		for (PcodeOp op : instr.getPcode()) {
			if (op.getOpcode() == PcodeOp.CALLOTHER) {
				int index = (int) op.getInput(0).getOffset();
				if (instr.getProgram().getLanguage().getUserDefinedOpName(index).equals("__m68k_trap")) {
					// TODO: check for trap #0
					return true;
				}
			}
		}
		
		return false;
	}
	
	/**
	 * Returns whether the given code unit is correctly set up to represent the function code of the specified syscall instruction.
	 * @param codeUnit
	 * @param instr
	 * @return
	 */
	protected boolean isCorrectFunctionCode(CodeUnit codeUnit, Instruction instr) {
		return (codeUnit != null && codeUnit.isSuccessor(instr) && codeUnit.getLength() == 2 && codeUnit instanceof Data);
	}
}
