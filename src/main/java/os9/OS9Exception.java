package os9;

public class OS9Exception extends Exception {
    /**
     * Constructs a new exception with the specified detail message.
     * @param   message   the detail message.
     */
	public OS9Exception(String message) {
		super(message);
	}

    /**
     * Constructs a new exception with the specified cause and a detail message.
     * @param  cause the cause (which is saved for later retrieval by the method
     */
	public OS9Exception(Exception cause) {
		super(cause);
	}
}
