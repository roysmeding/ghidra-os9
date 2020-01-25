package os9;

import java.util.HashMap;
import java.util.Map;

/**
 * Manages information about the different OS-9 system calls -- their function codes, names, descriptions, parameters, etc.
 * TODO: read this from some kind of data file, and add more information
 */
public class OS9SyscallInfo {
	protected Map<Integer, OS9Syscall> systemCalls;
	
	public OS9SyscallInfo() {
		systemCalls = new HashMap<Integer, OS9Syscall>();
		loadInfo();
	}
	
	public OS9Syscall get(int functionCode) {
		return systemCalls.get(functionCode);
	}
	
	protected void register(int functionCode, String name, String description) {
		systemCalls.put(functionCode, new OS9Syscall(functionCode, name, description));
	}
	
	protected void loadInfo() {
		register(0x00, "F$Link",     "Link to Module");
		register(0x01, "F$Load",     "Load Module from File");
		register(0x02, "F$UnLink",   "Unlink Module");
		register(0x03, "F$Fork",     "Start New Process");
		register(0x04, "F$Wait",     "Wait for Child Process to Die");
		register(0x05, "F$Chain",    "Chain Process to New Module");
		register(0x06, "F$Exit",     "Terminate Process");
		register(0x07, "F$Mem",      "Set Memory Size");
		register(0x08, "F$Send",     "Send Signal to Process");
		register(0x09, "F$Icpt",     "Set Signal Intercept");
		register(0x0a, "F$Sleep",    "Suspend Process");
		register(0x0b, "F$SSpd",     "Suspend Process");
		register(0x0c, "F$ID",       "Return Process ID");
		register(0x0d, "F$SPrior",   "Set Process Priority");
		register(0x0e, "F$STrap",    "Set Trap Intercept");
		register(0x0f, "F$PErr",     "Print Error");
		register(0x10, "F$PrsNam",   "Parse Pathlist Name");
		register(0x11, "F$CmpNam",   "Compare Two Names");
		register(0x12, "F$SchBit",   "Search Bit Map");
		register(0x13, "F$AllBit",   "Allocate in Bit Map");
		register(0x14, "F$DelBit",   "Deallocate in Bit Map");
		register(0x15, "F$Time",     "Get Current Time");
		register(0x16, "F$STime",    "Set Current Time");
		register(0x17, "F$CRC",      "Generate CRC");
		register(0x18, "F$GPrDsc",   "get Process Descriptor copy");
		register(0x19, "F$GBlkMp",   "get System Block Map copy");
		register(0x1a, "F$GModDr",   "get Module Directory copy");
		register(0x1b, "F$CpyMem",   "Copy External Memory");
		register(0x1c, "F$SUser",    "Set User ID number");
		register(0x1d, "F$UnLoad",   "Unlink Module by name");
		register(0x1e, "F$RTE",      "Return from Intercept routine");
		register(0x1f, "F$GPrDBT",   "Get system global data copy");
		register(0x20, "F$Julian",   "Convert gregorian to Julian date");
		register(0x21, "F$TLink",    "Link trap subroutine package");
		register(0x22, "F$DFork",    "Debugging Fork call");
		register(0x23, "F$DExec",    "Debugging execution call (single step)");
		register(0x24, "F$DExit",    "Debugging exit call (kill child)");
		register(0x25, "F$DatMod",   "Create data module");
		register(0x26, "F$SetCRC",   "Generate valid header and CRC in module");
		register(0x27, "F$SetSys",   "Set/examine system global variable");
		register(0x28, "F$SRqMem",   "System Memory Request");
		register(0x29, "F$SRtMem",   "System Memory Return");
		register(0x2a, "F$IRQ",      "Enter IRQ Polling Table");
		register(0x2b, "F$IOQu",     "Enter I/O Queue");
		register(0x2c, "F$AProc",    "Enter Active Process Queue");
		register(0x2d, "F$NProc",    "Start Next Process");
		register(0x2e, "F$VModul",   "Validate Module");
		register(0x2f, "F$FindPD",   "Find Process/Path Descriptor");
		register(0x30, "F$AllPD",    "Allocate Process/Path Descriptor");
		register(0x31, "F$RetPD",    "Return Process/Path Descriptor");
		register(0x32, "F$SSvc",     "Service Request Table Initialization");
		register(0x33, "F$IODel",    "Delete I/O Module");
		register(0x37, "F$GProcP",   "Get Process ptr");
		register(0x38, "F$Move",     "Move Data");
		register(0x39, "F$AllRAM",   "Allocate RAM blocks");
		register(0x3a, "F$Permit",   "(old F$AllImg) Allocate Image RAM blocks");
		register(0x3b, "F$Protect",  "(old F$DelImg) Deallocate Image RAM blocks");
		register(0x3f, "F$AllTsk",   "Allocate Process Task number");
		register(0x40, "F$DelTsk",   "Deallocate Process Task number");
		register(0x4b, "F$AllPrc",   "Allocate Process Descriptor");
		register(0x4c, "F$DelPrc",   "Deallocate Process Descriptor");
		register(0x4e, "F$FModul",   "Find Module Directory Entry");
		register(0x52, "F$SysDbg",   "Invoke system level debugger");
		register(0x53, "F$Event",    "Create/Link to named event");
		register(0x54, "F$Gregor",   "Convert julian date to gregorian date");
		register(0x55, "F$SysID",    "return system identification");
		register(0x56, "F$Alarm",    "send alarm signal");
		register(0x57, "F$SigMask",  "set signal mask");
		register(0x58, "F$ChkMem",   "determine if user process may access memory area");
		register(0x59, "F$UAcct",    "inform user accounting of process status");
		register(0x5a, "F$CCtl",     "cache control");
		register(0x5b, "F$GSPUMp",   "get SPU map information for a process");
		register(0x5c, "F$SRqCMem",  "System Colored Memory Request");
		register(0x5d, "F$POSK",     "execute svc request");
		register(0x5e, "F$Panic",    "Panic warning");
		register(0x5f, "F$MBuf",     "Memory buffer manager");
		register(0x60, "F$Trans",    "Translate memory address to/from external bus");
		register(0x61, "F$FIRQ",     "Add/Remove Fast IRQ service");
		register(0x62, "F$Sema",     "Semphore P/V (reserve/release) service");
		register(0x63, "F$SigReset", "Reset signal intercept context");
		register(0x64, "F$DAttach",  "Debugger attach to running process");
		register(0x65, "F$Flash",    "Manage FLASH device(s)");
		register(0x66, "F$PwrMan",   "Perform Power Management functions");
		register(0x67, "F$Crypt",    "Perform Cryptographic Functions");
		register(0x70, "F$HLProto",  "High-Level Protocol manager request");
		register(0x80, "I$Attach",   "Attach I/O Device");
		register(0x81, "I$Detach",   "Detach I/O Device");
		register(0x82, "I$Dup",      "Duplicate Path");
		register(0x83, "I$Create",   "Create New File");
		register(0x84, "I$Open",     "Open Existing File");
		register(0x85, "I$MakDir",   "Make Directory File");
		register(0x86, "I$ChgDir",   "Change Default Directory");
		register(0x87, "I$Delete",   "Delete File");
		register(0x88, "I$Seek",     "Change Current Position");
		register(0x89, "I$Read",     "Read Data");
		register(0x8a, "I$Write",    "Write Data");
		register(0x8b, "I$ReadLn",   "Read Line of ASCII Data");
		register(0x8c, "I$WritLn",   "Write Line of ASCII Data");
		register(0x8d, "I$GetStt",   "Get Path Status");
		register(0x8e, "I$SetStt",   "Set Path Status");
		register(0x8f, "I$Close",    "Close Path");
		register(0x92, "I$SGetSt",   "Getstat using system path number");
	}
}
