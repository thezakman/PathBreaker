package burp.model;

/**
 * Represents a single fuzzing result entry.
 */
public class FuzzResult {

    private final int index;
    private final String value;       // path or header value tested
    private final int statusCode;
    private final int responseLength;
    private final long responseTime;  // milliseconds
    private final String notes;

    public FuzzResult(int index, String value, int statusCode,
                      int responseLength, long responseTime, String notes) {
        this.index = index;
        this.value = value;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.responseTime = responseTime;
        this.notes = notes;
    }

    public int getIndex()          { return index; }
    public String getValue()       { return value; }
    public int getStatusCode()     { return statusCode; }
    public int getResponseLength() { return responseLength; }
    public long getResponseTime()  { return responseTime; }
    public String getNotes()       { return notes; }
}
