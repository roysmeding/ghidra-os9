package os9;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class OS9Header implements StructConverter {
	/**
	 * Program Module
	 */
	public final static int TYPE_PRGM = 1;

	/**
	 * Subroutine Module
	 */
	public final static int TYPE_SBRTN = 2;

	/**
	 * Multi-Module (reserved for future use
	 */
	public final static int TYPE_MULTI = 3;

	/**
	 * Data Module
	 */
	public final static int TYPE_DATA = 4;

	/**
	 * Configuration Status Descriptor
	 */
	public final static int TYPE_CSD_DATA = 5;

	/**
	 * User Trap Library
	 */
	public final static int TYPE_TRAP_LIB = 11;

	/**
	 * System Module (OS-9 component)
	 */
	public final static int TYPE_SYSTM = 12;

	/**
	 * File Manager Module
	 */
	public final static int TYPE_FLMGR = 13;

	/**
	 * Physical Device Driver
	 */
	public final static int TYPE_DRIVR = 14;

	/**
	 * Device Descriptor Module
	 */
	public final static int TYPE_DEVIC = 15;

	/**
	 * 68000 machine language
	 */
	public final static int LANG_OBJCT = 1;
	
	/**
	 * BASIC I-code
	 */
	public final static int LANG_I_CODE = 2;
	
	/**
	 * Pascal P-code
	 */
	public final static int LANG_P_CODE = 3;
	
	/**
	 * C I-code (reserved for future use
	 */
	public final static int LANG_C_CODE = 4;
	
	/**
	 * COBOL I-code
	 */
	public final static int LANG_CBL_CODE = 5;
	
	/**
	 * FORTRAN
	 */
	public final static int LANG_FRTN_CODE = 6;


    /**
     * Magic number
     */
	public final static int MAGIC = 0x4AFC;
	
	/**
	 * Magic number that identifies an OS-9 module.
	 */
	public int id;

	/**
	 * System revision identification
	 * <p>
	 * Identifies the format of a module.
	 */
	public int sysrev;

	/**
	 * Size of module
	 * <p>
	 * The overall module size in bytes, including header and CRC.
	 */
	public long size;

	/**
	 * Owner ID
	 * <p>
	 * The group/user ID of the module’s owner.
	 */
	public long owner;

	/**
	 * Offset to module name
	 * <p>
	 * The address of the module name string relative to the start (first sync byte)
	 * of the module. The name string can be located anywhere in the module and
	 * consists of a string of ASCII characters terminated by a null (zero) byte.
	 */
	public long name_offset;

	/**
	 * Access permissions
	 * <p>
	 * Defines the permissible module access by its owner or other users. Module
	 * access permissions are divided into four sections: reserved (4 bits) public
	 * (4 bits) group (4 bits) owner (4 bits)
	 * <p>
	 * Each of the non-reserved permission fields is defined as: bit 3 – reserved
	 * bit 2 – execute permission bit 1 – write permission bit 0 – read permission
	 * <p>
	 * The total field is displayed as: -----ewr-ewr-ewr
	 */
	public int accs;

	/**
	 * Module Type Code
	 * <p>
	 * Module type values are in the oskdefs.d file.
	 */
	public int type;

	/**
	 * Language
	 * <p>
	 * You can find module language codes in the oskdefs.d file. They describe
	 * whether the module is executable and which language the run-time system
	 * requires for execution (if any).
	 */
	public int lang;

	/**
	 * Attributes Bit 5 – Module is a “system state” module. Bit 6 – Module is a
	 * sticky module. A sticky module is retained in memory when its link count
	 * becomes zero. The module is removed from memory when its link count becomes
	 * -1 or memory is required for another use. Bit 7 – Module is re-entrant
	 * (sharable by multiple tasks).
	 */
	public int attr;

	/**
	 * Revision level
	 * <p>
	 * The module’s revision level. If two modules with the same name and type are
	 * found in the memory search or loaded into memory, only the module with the
	 * highest revision level is kept. This enables easy substitution of modules for
	 * update or correction, especially ROMed modules.
	 */
	public int revs;

	/**
	 * Edition
	 * <p>
	 * The software release level for maintenance. OS-9 does not use this field.
	 * Every time a program is revised (even for a small change), increase this
	 * number. We recommend that you key internal documentation within the source
	 * program to this system.
	 */
	public int edit;

	/**
	 * Comments
	 * <p>
	 * Reserved for offset to module usage comments (not currently used).
	 */
	public long usage;

	/**
	 * Symbol table offset
	 * <p>
	 * Reserved for future use.
	 */
	public long symbol;

	/**
	 * Header parity check
	 * <p>
	 * The one’s complement of the exclusive-OR of the previous header “words." OS-9
	 * uses this for a quick check of the module’s integrity.
	 */
	public int parity;

	/**
	 * Execution offset
	 * <p>
	 * The offset to the program’s starting address. In the case of a file manager
	 * or driver, this is the offset to the module’s entry table.
	 */
	public Long exec;

	/**
	 * Default user trap execution entry point
	 * <p>
	 * The relative address of a routine to execute if an uninitialized user trap is
	 * called.
	 */
	public Long excpt;

	/**
	 * Memory size
	 * <p>
	 * The required size of the program’s data area (storage for program variables).
	 */
	public Long mem;

	/**
	 * Stack size
	 * <p>
	 * The minimum required size of the program’s stack area.
	 */
	public Long stack;

	/**
	 * Initialized data offset
	 * <p>
	 * The offset to the initialization data area’s starting address. This area
	 * contains values to copy to the program’s data area. The linker places all
	 * constant values declared in vsects here. The first four-byte value is the
	 * offset from the beginning of the data area to which the initialized data is
	 * copied. The next four-byte value is the number of initialized data-bytes to
	 * follow.
	 */
	public Long idata;

	/**
	 * Initialized references offset
	 * <p>
	 * The offset to a table of values to locate pointers in the data area.
	 * Initialized variables in the program’s data area may contain values that are
	 * pointers to absolute addresses. Adjust code pointers by adding the absolute
	 * starting address of the object code area. Adjust the data pointers by adding
	 * the absolute starting address of the data area.
	 * <p>
	 * The F$Fork system call does the effective address calculation at execution
	 * time using tables created in the module. The first word of each table is the
	 * most significant (MS) word of the offset to the pointer. The second word is a
	 * count of the number of least significant (LS) word offsets to adjust. F$Fork
	 * makes the adjustment by combining the MS word with each LS word entry. This
	 * offset locates the pointer in the data area. The pointer is adjusted by
	 * adding the absolute starting address of the object code or the data area (for
	 * code pointers or data pointers respectively). It is possible after exhausting
	 * this first count that another MS word and LS word are given. This continues
	 * until a MS word of zero and a LS word of zero are found.
	 */
	public Long irefs;

	/**
	 * Initialization execution offset
	 * <p>
	 * The offset to the trap initialization entry point.
	 */
	public Long init;

	/**
	 * Termination execution offset
	 * <p>
	 * The offset to the trap termination entry point. This offset is reserved by
	 * Microware for future use.
	 */
	public Long term;
	
	public static OS9Header fromProvider(ByteProvider provider, long offset) throws IOException, OS9Exception {
		var reader = new BinaryReader(provider, false);
		reader.setPointerIndex(offset);
		return new OS9Header(reader);
	}

	public OS9Header(BinaryReader reader) throws IOException, OS9Exception {
		// store offset for computing parity
		long start_offset = reader.getPointerIndex();
		
		id = reader.readNextUnsignedShort();
		
		if (id != MAGIC) {
			throw new OS9Exception("Invalid magic number for OS-9 module");
		}
		
		sysrev = reader.readNextUnsignedShort();
		size = reader.readNextUnsignedInt();
		owner = reader.readNextUnsignedInt();
		name_offset = reader.readNextUnsignedInt();
		accs = reader.readNextUnsignedShort();
		type = reader.readNextUnsignedByte();
		lang = reader.readNextUnsignedByte();
		attr = reader.readNextUnsignedByte();
		revs = reader.readNextUnsignedByte();
		edit = reader.readNextUnsignedShort();
		usage = reader.readNextUnsignedInt();
		symbol = reader.readNextUnsignedInt();
		reader.readNextByteArray(14);
		
		int actualParity = 0xFFFF;
		reader.setPointerIndex(start_offset);
		for (int i = 0; i < 0x2e; i += 2) {
			actualParity ^= reader.readNextUnsignedShort();
		}
		
		parity = reader.readNextUnsignedShort();
		
		if (parity != actualParity) {
			throw new OS9Exception("Invalid parity word for OS-9 module (file: " + parity + ", actual: " + actualParity + ")");
		}

		if (type == TYPE_FLMGR || type == TYPE_SYSTM || type == TYPE_DRIVR || type == TYPE_PRGM
				|| type == TYPE_TRAP_LIB) {
			exec = reader.readNextUnsignedInt();
			excpt = reader.readNextUnsignedInt();
		}

		if (type == TYPE_DRIVR || type == TYPE_PRGM || type == TYPE_TRAP_LIB) {
			mem = reader.readNextUnsignedInt();
		}

		if (type == TYPE_PRGM || type == TYPE_TRAP_LIB) {
			stack = reader.readNextUnsignedInt();
			idata = reader.readNextUnsignedInt();
			irefs = reader.readNextUnsignedInt();
		}

		if (type == TYPE_TRAP_LIB) {
			init = reader.readNextUnsignedInt();
			term = reader.readNextUnsignedInt();
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("os9_header", 0);
		struct.add(WORD, 2, "magic", null);
		struct.add(WORD, 2, "sysrev", null);
		struct.add(DWORD, 4, "size", null);
		struct.add(DWORD, 4, "owner", null);
		struct.add(DWORD, 4, "name_offset", null);
		struct.add(WORD, 2, "accs", null);
		struct.add(BYTE, 1, "type", null);	// TODO: enum?
		struct.add(BYTE, 1, "lang", null);	// TODO: enum?
		struct.add(BYTE, 1, "attr", null);
		struct.add(BYTE, 1, "revs", null);
		struct.add(WORD, 2, "edit", null);
		struct.add(DWORD, 4, "usage", null);
		struct.add(DWORD, 4, "symbol", null);
		
		struct.add(VOID, 14, null, null);
		struct.add(WORD, 2, "parity", null);

		if (exec != null) {
			struct.add(DWORD, 4, "exec", null);
		}

		if (excpt != null) {
			struct.add(DWORD, 4, "excpt", null);
		}

		if (mem != null) {
			struct.add(DWORD, 4, "mem", null);
		}

		if (stack != null) {
			struct.add(DWORD, 4, "stack", null);
		}

		if (idata != null) {
			struct.add(DWORD, 4, "idata", null);
		}

		if (irefs != null) {
			struct.add(DWORD, 4, "irefs", null);
		}

		if (init != null) {
			struct.add(DWORD, 4, "init", null);
		}

		if (term != null) {
			struct.add(DWORD, 4, "term", null);
		}

		return struct;
	}
}
