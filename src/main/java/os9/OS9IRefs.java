package os9;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class OS9IRefs implements StructConverter {
	/**
	 * A list of offsets into the data block that should be adjusted by the module area offset on module load
	 */
	public List<IRefList> code_refs;
	
	/**
	 * A list of offsets into the data block that should be adjusted by the data area offset on module load
	 */
	public List<IRefList> data_refs;

	public OS9IRefs(BinaryReader reader) throws IOException {
		code_refs = readTable(reader);
		data_refs = readTable(reader);
	}
	

	public static OS9IRefs fromProvider(ByteProvider provider, long offset) throws IOException {
		var reader = new BinaryReader(provider, false);
		reader.setPointerIndex(offset);
		
		return new OS9IRefs(reader);
	}
	
	private List<IRefList> readTable(BinaryReader reader) throws IOException {
		var result = new ArrayList<IRefList>();
		
		while(true) {
			var sublist = new IRefList(reader);
			if (sublist.getNumEntries() == 0) {
				break;
			}
			result.add(sublist);
		}
		
		return result;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {		
		var codeRefs = new StructureDataType("code_refs", 0);
		for (var ref : code_refs) {
			codeRefs.add(ref.toDataType());
		}
		codeRefs.add(WORD, null, "end of table");
		codeRefs.add(WORD);
		
		var dataRefs = new StructureDataType("data_refs", 0);
		for (var ref : data_refs) {
			dataRefs.add(ref.toDataType());
		}
		dataRefs.add(WORD, null, "end of table");
		dataRefs.add(WORD);
		
		var irefs = new StructureDataType("os9_irefs", 0);
		irefs.add(codeRefs);
		irefs.add(dataRefs);
		
		return irefs;
	}
}
