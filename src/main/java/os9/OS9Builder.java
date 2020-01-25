package os9;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads a single OS9 module into a Program
 */
public class OS9Builder {
	protected Program program;
	protected Memory memory;
	protected ReferenceManager referenceManager;
	protected SymbolTable symbolTable;
	protected Listing listing;
	
	protected TaskMonitor monitor;
	protected MessageLog log;
	
	protected boolean registerEntryPoints = true;
	protected boolean useIData = true;
	protected boolean useIRefs = true;
	protected boolean assumeA6 = true;
	
	protected AddressSet loadedData;
	
	public OS9Builder(Program program, TaskMonitor monitor, MessageLog log)
	{
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		
		symbolTable = program.getSymbolTable();
		referenceManager = program.getReferenceManager();
		memory = program.getMemory();
		listing = program.getListing();
		
		loadedData = new AddressSet();
	}
	
	public void setRegisterEntryPoints(boolean value) {
		registerEntryPoints = value;
	}

	public void setUseIData(boolean value) {
		useIData = value;
	}

	public void setUseIRefs(boolean value) {
		useIRefs = value;
	}
	
	public void setAssumeA6(boolean value) {
		assumeA6 = value;
	}
	
	public void load(OS9Header header, ByteProvider provider, long moduleOffset, Long dataOffset)
			throws CancelledException, IOException, UsrException {
			
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address moduleAddress = addressSpace.getAddress(moduleOffset);
		
		loadModuleArea(header, moduleAddress, provider);
		
		if (header.mem != null) {
			Address dataAddress = addressSpace.getAddress(dataOffset);

			loadDataArea(header, dataAddress);
		
			if (header.idata != null) {
				loadIData(header, provider, moduleAddress, dataAddress);
			}
			
			loadIRefs(header, provider, moduleAddress, dataAddress);
			
			if (assumeA6) {
				Long A6Offset = 0x8000L;
				var A6Value = dataAddress.getOffsetAsBigInteger().add(new BigInteger(A6Offset.toString()));
				program.getProgramContext().setValue(program.getRegister("A6"), loadedData.getMinAddress(), loadedData.getMaxAddress(), A6Value);
				Msg.debug(this, "Assuming " + program.getRegister("A6").toString() + " = " + A6Value.toString(16));
			}
		}
		
		createEntryPoint("exec", moduleAddress.add(header.exec));
		createEntryPoint("excpt", moduleAddress.add(header.excpt));
	}
	
	protected void loadModuleArea(OS9Header header, Address address, ByteProvider provider) throws UsrException, IOException
	{
		log.appendMsg("Loading module area at " + address);
		
		InputStream fileIn = provider.getInputStream(0);
		FileBytes fileBytes = memory.createFileBytes(provider.getName(), 0, provider.length(), fileIn, monitor);
		
		MemoryBlock moduleBlock = memory.createInitializedBlock("module", address, fileBytes, 0, header.size, false);
		loadedData.add(address, address.add(header.size));
		moduleBlock.setPermissions(true, false, true);

		// create labels and structs and references
		symbolTable.createLabel(address, "module_start", SourceType.IMPORTED);
		DataUtilities.createData(program, address, header.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		DataUtilities.createData(program, address.add(header.name_offset), new StringDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		DataUtilities.createData(program, address.add(header.size - 4), new DWordDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		listing.setComment(address.add(header.size - 4), CodeUnit.EOL_COMMENT, "CRC");
		
		referenceManager.addMemoryReference(address.add(0x30), address.add(header.exec), RefType.EXTERNAL_REF, SourceType.IMPORTED, 0);
		referenceManager.addMemoryReference(address.add(0x34), address.add(header.excpt), RefType.EXTERNAL_REF, SourceType.IMPORTED, 0);
		referenceManager.addMemoryReference(address.add(0x40), address.add(header.idata), RefType.EXTERNAL_REF, SourceType.IMPORTED, 0);
		referenceManager.addMemoryReference(address.add(0x44), address.add(header.irefs), RefType.EXTERNAL_REF, SourceType.IMPORTED, 0);
	}
	
	protected void loadDataArea(OS9Header header, Address address) throws UsrException
	{
		log.appendMsg("Loading data area at " + address);
		
		// create variable area
		MemoryBlock dataBlock = memory.createInitializedBlock("data", address, header.mem, (byte) 0x00, monitor, false);
		dataBlock.setPermissions(true, true, true);
		Address var_top = address.add(header.mem);
		symbolTable.createLabel(address, "data_start", SourceType.IMPORTED);
		loadedData.add(address, var_top);
		
		// create stack area
		MemoryBlock stackBlock = memory.createUninitializedBlock("stack", var_top, header.stack, false);
		stackBlock.setPermissions(true, true, true);
		Address stack_top = var_top.add(header.stack);
		symbolTable.createLabel(stack_top, "stack_top", SourceType.IMPORTED);
		loadedData.add(var_top, stack_top);
		
		// create params area
		var params_length = OS9Loader.DEFAULT_PARAMS_LENGTH;
		MemoryBlock paramsBlock = memory.createUninitializedBlock("params", stack_top, params_length, false);
		Address data_top = stack_top.add(params_length);
		symbolTable.createLabel(data_top, "data_top", SourceType.IMPORTED);
		loadedData.add(stack_top, data_top);
	}
	
	protected void loadIData(OS9Header header, ByteProvider provider, Address moduleAddress, Address dataAddress)
			throws IOException, UsrException {
		OS9IDataHeader idata = OS9IDataHeader.fromProvider(provider, header.idata);

		symbolTable.createLabel(moduleAddress.add(header.idata), "idata", SourceType.IMPORTED);
		DataUtilities.createData(program, moduleAddress.add(header.idata), idata.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		
		if (useIData) {
			// TODO: this seems ugly
			byte[] idataBytes = provider.readBytes(header.idata + 8, idata.length);
			memory.setBytes(dataAddress.add(idata.offset), idataBytes);
			referenceManager.addMemoryReference(moduleAddress.add(header.idata), dataAddress.add(idata.offset), RefType.WRITE, SourceType.IMPORTED, 0);
		}
	}
	
	protected void loadIRefs(OS9Header header, ByteProvider provider, Address moduleAddress, Address dataAddress)
			throws IOException, UsrException {
		
		var relocationTable = program.getRelocationTable();
		// load irefs data
		OS9IRefs irefs = OS9IRefs.fromProvider(provider, header.irefs);
		
		// tag irefs with struct / refs
		symbolTable.createLabel(moduleAddress.add(header.irefs), "irefs", SourceType.IMPORTED);
		DataUtilities.createData(program, moduleAddress.add(header.irefs), irefs.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		
		// handle relocations
		long iref_entry_offset = header.irefs; // offset of the actual iref entry within irefs
		
		for (IRefList code_ref_list : irefs.code_refs) {
			iref_entry_offset += 4;	// skip msw / n_lsws
			
			for (long offset : code_ref_list.getOffsets()) {
				monitor.checkCanceled();
				
				// do relocation
				Address entryAddr = moduleAddress.add(iref_entry_offset);						// address of the iref entry
				Address relocAddr = dataAddress.add(offset);									// address of the pointer to be modified
				Address pointerAddr = moduleAddress.add(memory.getInt(relocAddr));	// address of the target of the pointer
				long[] values = new long[] { };
				byte[] bytes = new byte[4];
				
				memory.getBytes(relocAddr, bytes);
				memory.setInt(relocAddr, (int) pointerAddr.getOffset());
				relocationTable.add(relocAddr, 1, values, bytes, null);

				referenceManager.addMemoryReference(entryAddr, relocAddr, RefType.WRITE, SourceType.IMPORTED, 0);
				referenceManager.addMemoryReference(relocAddr, pointerAddr, RefType.DATA, SourceType.IMPORTED, 0);
				
				iref_entry_offset += 2;
			}
		}
		
		iref_entry_offset += 4;	// skip the two zero words that indicate the end of the table

		for (IRefList data_ref_list : irefs.data_refs) {
			iref_entry_offset += 4;	// skip msw / n_lsws
			
			for (long offset : data_ref_list.getOffsets()) {
				monitor.checkCanceled();
				
				// do relocation
				Address entryAddr = moduleAddress.add(iref_entry_offset);						// address of the iref entry
				Address relocAddr = dataAddress.add(offset);									// address of the pointer to be modified
				Address pointerAddr = dataAddress.add(memory.getInt(relocAddr));	// address of the target of the pointer
				long[] values = new long[] { };
				byte[] bytes = new byte[4];
				
				memory.getBytes(relocAddr, bytes);
				memory.setInt(relocAddr, (int) pointerAddr.getOffset());
				program.getRelocationTable().add(relocAddr, 2, values, bytes, null);

				referenceManager.addMemoryReference(entryAddr, relocAddr, RefType.WRITE, SourceType.IMPORTED, 0);
				referenceManager.addMemoryReference(relocAddr, pointerAddr, RefType.DATA, SourceType.IMPORTED, 0);
				
				iref_entry_offset += 2;
			}
		}
	}
	
	protected void createEntryPoint(String name, Address address)
	{
		try {
			symbolTable.createLabel(address, name, SourceType.IMPORTED);
			
			if (registerEntryPoints) {
				symbolTable.addExternalEntryPoint(address);
				listing.createFunction(name, address, new AddressSet(address), SourceType.IMPORTED);
			}			
		} catch (InvalidInputException | OverlappingFunctionException e) {
			log.appendException(e);
		}
	}
}
