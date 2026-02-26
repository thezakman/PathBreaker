package pathbreaker;

import java.util.Set;

public class FuzzResult {
    private static final Set<Integer> INTERESTING = Set.of(200, 201, 206, 301, 302, 307, 308);
    private static final int MAX_BODY = 512 * 1024; // 500 KB

    public final String label;
    public final String rawPath;
    public final Integer statusCode;
    public final int bodyLength;
    public final String responseHeaders;
    public final String responseBody;
    public String note;
    public final boolean isInteresting;
    public final String rawRequest;
    public final burp.api.montoya.http.message.HttpRequestResponse reqResp;

    public FuzzResult(String label, String rawPath, Integer statusCode,
            int bodyLength, String responseHeaders, String responseBody,
            String note, String rawRequest, burp.api.montoya.http.message.HttpRequestResponse reqResp) {
        this.label = label;
        this.rawPath = rawPath;
        this.statusCode = statusCode;
        this.bodyLength = bodyLength;
        this.responseHeaders = responseHeaders != null ? responseHeaders : "";
        this.note = note != null ? note : "";
        this.rawRequest = rawRequest != null ? rawRequest : "";
        this.reqResp = reqResp;

        // Truncate body to 500KB
        if (responseBody != null && responseBody.length() > MAX_BODY) {
            this.responseBody = responseBody.substring(0, MAX_BODY) + "\n\n[... truncated]";
        } else {
            this.responseBody = responseBody != null ? responseBody : "";
        }

        this.isInteresting = statusCode != null && INTERESTING.contains(statusCode);
    }

    public static FuzzResult error(String label, String rawPath, String note, String rawRequest) {
        return new FuzzResult(label, rawPath, null, 0, "", "", note, rawRequest, null);
    }
}
