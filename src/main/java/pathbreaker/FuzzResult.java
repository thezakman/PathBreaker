package pathbreaker;

import java.util.Set;

public class FuzzResult {
    private static final Set<Integer> INTERESTING = Set.of(200, 201, 206, 301, 302, 307, 308);
    private static final int MAX_BODY = 512 * 1024; // 500 KB

    public final String label;
    public final String rawPath;
    public final Integer statusCode;
    public final int bodyLength;
    public String note;
    public final boolean isInteresting;
    public final burp.api.montoya.http.message.HttpRequestResponse reqResp;

    public FuzzResult(String label, String rawPath, Integer statusCode,
            int bodyLength, String note, burp.api.montoya.http.message.HttpRequestResponse reqResp) {
        this.label = label;
        this.rawPath = rawPath;
        this.statusCode = statusCode;
        this.bodyLength = bodyLength;
        this.note = note != null ? note : "";
        this.reqResp = reqResp;

        this.isInteresting = statusCode != null && INTERESTING.contains(statusCode);
    }

    public static FuzzResult error(String label, String rawPath, String note) {
        return new FuzzResult(label, rawPath, null, 0, note, null);
    }
}
