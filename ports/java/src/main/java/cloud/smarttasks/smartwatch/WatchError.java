package cloud.smarttasks.smartwatch;

/** A refused input; {@link #code} is the stable WATCH-* code (WATCH-BAD-EVENT, WATCH-BAD-POLICY). */
public final class WatchError extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;
    public final String code;

    public WatchError(String code, String message) {
        super(code + ": " + message);
        this.code = code;
    }
}
