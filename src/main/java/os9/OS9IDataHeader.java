package os9;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Header of the Initialized Data (IData) section of an OS9 program module.
 */
public class OS9IDataHeader implements StructConverter {
	public long offset;
	public long length;

	public static OS9IDataHeader fromProvider(ByteProvider provider, long idata) throws IOException {
		var reader = new BinaryReader(provider, false);
		reader.setPointerIndex(idata);
		return new OS9IDataHeader(reader);
	}
	
	public OS9IDataHeader(BinaryReader reader) throws IOException {
		offset = reader.readNextUnsignedInt();
		length = reader.readNextUnsignedInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		var struct = new StructureDataType("os9_idata", 0);
		struct.add(DWORD, 4, "offset", null);
		struct.add(DWORD, 4, "length", null);
		return struct;
	}
}
