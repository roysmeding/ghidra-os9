package os9;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Implements the 24-bit CRC used by OS-9 modules.
 */
public class OS9CRC {
	public static int POLYNOMIAL = 0x00800063;
	protected static int MASK = (1 << 24) - 1;
	
	protected int accumulator;
	
	/**
	 * 256-entry lookup table for the CRC value for each byte
	 */
	protected int[] table;
	
	public OS9CRC() {
		buildTable();
		reset();
	}
	
	protected void buildTable() {
		table = new int[256];
		
		int crc = 1 << 23;
		
		table[0] = 0;
		for (int i = 1; i < 256; i <<= 1) {
			crc <<= 1;
			if ((crc & (1 << 24)) != 0) {
				crc ^= POLYNOMIAL;
			}
			
			for (int j = 0; j < i; j += 1) {
				table[i + j] = crc ^ table[j];
			}
		}
	}
	
	/**
	 * Reset the state to start computing a new CRC value
	 */
	public void reset() {
		accumulator = MASK;
	}
	
	/**
	 * @param provider
	 * @param offset
	 * @param length
	 * @throws IOException
	 * @throws CancelledException
	 */
	public void feed(ByteProvider provider, long offset, long length) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		reader.setPointerIndex(offset);
				
		for (long i = 0; i < length; i += 1) {
			byte data = reader.readNextByte();
			
			int idx = ((accumulator >> 16) ^ data) & 0xFF;
			accumulator = (accumulator << 8) ^ table[idx];
		}
	}
	
	/**
	 * @return The CRC value
	 */
	public int getResult() {
		return (MASK ^ (accumulator & MASK));
	}
	
	public byte[] getResultAsBytes() {
		int result = getResult();
		return new byte[] {
			(byte) ((result >> 16) & 0xff),
			(byte) ((result >>  8) & 0xff),
			(byte) ( result        & 0xff),
		}; 
	}
}
