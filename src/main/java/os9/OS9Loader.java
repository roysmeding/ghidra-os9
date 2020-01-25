package os9;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.CommentTypes;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.reloc.RelocationUtil;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.CommentType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads an OS-9 module file.
 */
public class OS9Loader extends AbstractLibrarySupportLoader {
	public static final String LOADER_NAME = "OS-9 module loader";

	public static final String MODULE_OFFSET_OPTION = "Module area offset";

	public static final String DATA_OFFSET_OPTION = "Data area offset";

	public static final String IREFS_OPTION = "Perform relocations using IRefs";

	public static final String ENTRYPOINTS_OPTION = "Register entrypoints";

	public static final String IDATA_OPTION = "Initialize data area using IData";
	
	public static final String ASSUME_A6_OPTION = "Add ASSUME for register A6 to point to data area across all of memory";

	/**
	 * Default virtual address offset to load the data area at 
	 */
	public static long DEFAULT_DATA_START = 0x1000;
	
	/**
	 * Amount of space to leave for module parameters when computing a default virtual address offset for the module data
	 */
	public static long DEFAULT_PARAMS_LENGTH = 0x100;
	
	/**
	 * Multiple to align the default module data start offset to, to make mental arithmetic easier.
	 */
	public static long DEFAULT_MODULE_START_ALIGN = 0x1000;

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		var loadSpecs = new ArrayList<LoadSpec>();

		try {
			var header = OS9Header.fromProvider(provider, 0);
			
//			boolean validCRC = checkCRC(header, provider, 0);
			
			if (header.type == OS9Header.TYPE_PRGM) {
				if (header.lang == OS9Header.LANG_OBJCT) {
					// TODO: we can probably support more
					loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
				} else {
					loadSpecs.add(new LoadSpec(this, 0, true));
				}
			} else {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		} catch (OS9Exception exception) {
			Msg.debug(this, "Failed to recognize OS9 header: " + exception.getLocalizedMessage());
		}

		return loadSpecs;
	}

	protected boolean checkCRC(OS9Header header, ByteProvider provider, long offset) throws IOException {
		var crc = new OS9CRC();
		crc.feed(provider, offset, header.size - 3);
		
		byte[] desiredResult = provider.readBytes(offset+header.size-3, 3);
		return crc.getResultAsBytes().equals(desiredResult);
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		try {
			var builder = new OS9Builder(program, monitor, log);
			
			Long moduleOffset = null, dataOffset = null;
			
			for (Option option : options) {
				switch (option.getName()) {
					case ENTRYPOINTS_OPTION:
						builder.setRegisterEntryPoints((boolean) option.getValue());
						break;
						
					case IDATA_OPTION:
						builder.setUseIData((boolean) option.getValue());
						break;
						
					case IREFS_OPTION:
						builder.setUseIRefs((boolean) option.getValue());
						break;
						
					case ASSUME_A6_OPTION:
						builder.setAssumeA6((boolean) option.getValue());
						break;
						
					case MODULE_OFFSET_OPTION:
						moduleOffset = (long) option.getValue();
						break;
						
					case DATA_OFFSET_OPTION:
						dataOffset = (long) option.getValue();
						break;
				}
			}
			
			OS9Header header = OS9Header.fromProvider(provider, 0);
			builder.load(header, provider, moduleOffset, dataOffset);
			
		} catch (OS9Exception | UsrException e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public List<Option> getDefaultOptions(
		ByteProvider provider,
		LoadSpec loadSpec,
		DomainObject domainObject, 
		boolean isLoadIntoProgram
	) {
		List<Option> options = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		
		try {
			var header = OS9Header.fromProvider(provider, 0);
			
			if (header.exec != null) {
				options.add(new Option(ENTRYPOINTS_OPTION, true));
			}
			
			if (header.idata != null) {
				options.add(new Option(IDATA_OPTION, true));
				
				// this isn't the most untuitive check, but if we have idata, it makes sense to have memory references
				options.add(new Option(ASSUME_A6_OPTION, true));
			}
			
			if (header.irefs != null) {
				options.add(new Option(IREFS_OPTION, true));
			}
			
			if (header.mem != null) {
				long dataSize = DEFAULT_PARAMS_LENGTH + header.mem;
				if (header.stack != null) dataSize += header.stack;
		
				// some space for parameters, round up to next multiple of 0x1000 to make mental arithmetic easier
				long moduleAreaOffset = (((DEFAULT_DATA_START + dataSize) / DEFAULT_MODULE_START_ALIGN) + 1) * DEFAULT_MODULE_START_ALIGN;
				
				options.add(new Option(DATA_OFFSET_OPTION, DEFAULT_DATA_START));
				options.add(new Option(MODULE_OFFSET_OPTION, moduleAreaOffset));
			} else {
				options.add(new Option(MODULE_OFFSET_OPTION, 0));
			}
			
		} catch (Exception e) {
			Msg.error(this, "Error while generating OS-9 module default import options", e);
		}
		
		return options;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		try {
			var header = OS9Header.fromProvider(provider, 0);
			
			Long dataOffset = 0L, moduleOffset = 0L;
			
			for (Option option : options) {
				String name = option.getName();
				if (
					name.equals(ENTRYPOINTS_OPTION)
					|| name.equals(IDATA_OPTION)
					|| name.equals(IREFS_OPTION)
					|| name.equals(ASSUME_A6_OPTION)
				) {
					if (! Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
				
				if (name.equals(DATA_OFFSET_OPTION) || name.equals(MODULE_OFFSET_OPTION)) {
					if (! Long.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
					
					if (name.contentEquals(DATA_OFFSET_OPTION)) {
						dataOffset = (Long) option.getValue();
					}
					
					if (name.contentEquals(MODULE_OFFSET_OPTION)) {
						moduleOffset = (Long) option.getValue();
					}
				}
			}
			
			if (header.mem != null) {
				// data and module can't overlap
				long dataSize = header.mem;
				if (header.stack != null) dataSize += header.stack;
		
				if (rangesOverlap(moduleOffset, moduleOffset + header.size, dataOffset, dataOffset + dataSize)) {
					return "Specified module and data offsets result in overlap";
				}
			}
			
		} catch (Exception e) {
			Msg.error(this, "Error while validating OS-9 module import options", e);
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	private boolean rangesOverlap(long startA, long endA, long startB, long endB) {
		return (inRange(startA, startB, endB) || inRange(endA, startB, endB) || inRange(startB, startA, endA) || inRange(endB, startA, endA));
	}
	
	private boolean inRange(long value, long start, long end) {
		return ((value >= start) && (value < end));
	}
}
