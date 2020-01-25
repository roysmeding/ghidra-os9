package os9;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class IRefList implements StructConverter {
	public int msw;
	public int[] lsws;

	public IRefList(BinaryReader reader) throws IOException {
		super();
		
		msw = reader.readNextUnsignedShort();
		int n_lsw = reader.readNextUnsignedShort();
		
		if (msw == 0 && n_lsw == 0) {
			return;
		}
		
		lsws = new int[n_lsw];
		
		for (int i = 0; i < n_lsw; i += 1) {
			lsws[i] = reader.readNextUnsignedShort();
		}
	}
	
	public int getNumEntries() {
		return (lsws == null) ? 0 : lsws.length;
	}
	
	public List<Long> getOffsets() {
		if (lsws == null) {
			return null;
		}
		
		var offsets = new ArrayList<Long>(lsws.length);
		for (int lsw : lsws) {
			offsets.add(((long) msw << 16) | lsw);
		}
		return offsets;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		var struct = new StructureDataType("iref_list", 0);
		struct.add(WORD, "msw", null);
		struct.add(WORD, "n_lsws", null);
		for (int i = 0; i < lsws.length; i += 1) {
			struct.add(WORD, "lsw", null);
		}
		return struct;
	}
}
