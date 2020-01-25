package os9;

/**
 * Information about a single OS-9 system call.
 */
public class OS9Syscall {
	public int functionCode;
	public String name;
	public String description;

	public OS9Syscall(int functionCode, String name, String description) {
		this.functionCode = functionCode;
		this.name = name;
		this.description = description;
	}
}
