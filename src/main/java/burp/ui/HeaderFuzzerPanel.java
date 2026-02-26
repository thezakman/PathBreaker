package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.model.FuzzResult;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Header Fuzzer panel – tests different header names/values against a target
 * URL and records each response.  Supports two modes:
 * <ul>
 *   <li><b>Single Header</b>: fuzz the value of one specific header.</li>
 *   <li><b>Header Pairs</b>: each wordlist line is a full {@code Name: Value}
 *       pair injected into the request.</li>
 * </ul>
 */
public class HeaderFuzzerPanel extends JPanel {

    // -------------------------------------------------------------------------
    // Fields – UI controls
    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    private static final int MAX_THREADS  = 50;
    private static final int MAX_DELAY_MS = 60_000;

    // -------------------------------------------------------------------------
    // Fields – UI controls
    // -------------------------------------------------------------------------
    private final JTextField urlField            = new JTextField(40);
    private final JComboBox<String> methodCombo  = new JComboBox<>(new String[]{"GET","POST","HEAD","OPTIONS","PUT"});
    private final JTextArea  baseHeadersArea     = new JTextArea(3, 40);
    private final JTextArea  bodyArea            = new JTextArea(2, 40);

    private final JRadioButton singleModeRadio = new JRadioButton("Single Header", true);
    private final JRadioButton pairsModeRadio  = new JRadioButton("Header Pairs");
    private final JTextField   headerNameField = new JTextField("X-Forwarded-For", 22);

    private final JRadioButton builtinRadio = new JRadioButton("Built-in", true);
    private final JRadioButton fileRadio    = new JRadioButton("File");
    private final JTextField   fileField    = new JTextField(28);
    private final JButton      browseBtn    = new JButton("Browse…");

    private final JSpinner  threadsSpinner   = new JSpinner(new SpinnerNumberModel(5, 1, MAX_THREADS, 1));
    private final JSpinner  delaySpinner     = new JSpinner(new SpinnerNumberModel(0, 0, MAX_DELAY_MS, 100));
    private final JCheckBox followRedirCheck = new JCheckBox("Follow Redirects", false);
    private final JTextField filterField     = new JTextField("", 20);

    private final JButton startBtn  = new JButton("▶  Start");
    private final JButton stopBtn   = new JButton("■  Stop");
    private final JButton clearBtn  = new JButton("Clear");
    private final JButton exportBtn = new JButton("Export CSV");

    private final JProgressBar      progressBar = new JProgressBar();
    private final JLabel            statusLabel = new JLabel("Ready");
    private final ResultsTableModel tableModel  = new ResultsTableModel();
    private final JTable            resultsTable;

    // -------------------------------------------------------------------------
    // Fields – runtime
    // -------------------------------------------------------------------------
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ExecutorService executor;

    // Stored raw request bytes (when loaded from another tool via context menu)
    private byte[] baseRequestBytes;
    private String savedHost;
    private int    savedPort;
    private boolean savedHttps;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public HeaderFuzzerPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks    = callbacks;
        this.helpers      = helpers;
        this.resultsTable = new JTable(tableModel);
        tableModel.applyTo(resultsTable);
        buildUI();
        wireActions();
    }

    // -------------------------------------------------------------------------
    // Public API – context menu
    // -------------------------------------------------------------------------
    public void loadRequest(IHttpRequestResponse message) {
        if (message == null) return;
        var service = message.getHttpService();
        if (service == null) return;

        savedHost   = service.getHost();
        savedPort   = service.getPort();
        savedHttps  = "https".equalsIgnoreCase(service.getProtocol());
        baseRequestBytes = message.getRequest();

        // Fill URL field for display
        boolean defaultPort = (savedHttps && savedPort == 443) || (!savedHttps && savedPort == 80);
        String proto = savedHttps ? "https" : "http";
        String displayUrl = proto + "://" + savedHost
            + (defaultPort ? "" : ":" + savedPort) + "/";

        if (baseRequestBytes != null) {
            IRequestInfo info = helpers.analyzeRequest(baseRequestBytes);
            displayUrl = proto + "://" + savedHost
                + (defaultPort ? "" : ":" + savedPort)
                + info.getUrl().getPath();
        }
        urlField.setText(displayUrl);

        JOptionPane.showMessageDialog(this,
            "Request loaded from Burp.\nURL: " + displayUrl,
            "PathBreaker – Header Fuzzer", JOptionPane.INFORMATION_MESSAGE);
    }

    // -------------------------------------------------------------------------
    // UI construction
    // -------------------------------------------------------------------------
    private void buildUI() {
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout(6, 6));
        top.add(buildTargetPanel(),  BorderLayout.NORTH);
        top.add(buildFuzzPanel(),    BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, buildResultsPanel());
        split.setDividerLocation(340);
        split.setResizeWeight(0.35);

        add(split, BorderLayout.CENTER);
    }

    private JPanel buildTargetPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Request Configuration"));

        p.add(new JLabel("URL:"), lc(0, 0));
        GridBagConstraints fc = fc(1, 0, 3);
        p.add(urlField, fc);

        p.add(new JLabel("Method:"), lc(0, 1));
        p.add(methodCombo, fc(1, 1, 1));

        p.add(new JLabel("Base Headers:"), lc(0, 2));
        JScrollPane sp1 = new JScrollPane(baseHeadersArea);
        sp1.setPreferredSize(new Dimension(400, 55));
        GridBagConstraints fc2 = fc(1, 2, 3);
        p.add(sp1, fc2);

        p.add(new JLabel("Body:"), lc(0, 3));
        JScrollPane sp2 = new JScrollPane(bodyArea);
        sp2.setPreferredSize(new Dimension(400, 40));
        p.add(sp2, fc(1, 3, 3));

        return p;
    }

    private JPanel buildFuzzPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Header Fuzzing Options"));

        ButtonGroup mg = new ButtonGroup();
        mg.add(singleModeRadio); mg.add(pairsModeRadio);

        singleModeRadio.addActionListener(e -> headerNameField.setEnabled(true));
        pairsModeRadio.addActionListener(e  -> headerNameField.setEnabled(false));

        JPanel modeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        modeRow.add(singleModeRadio); modeRow.add(pairsModeRadio);
        modeRow.add(new JLabel("  Header Name:"));
        modeRow.add(headerNameField);
        GridBagConstraints fcc = fc(1, 0, 3);
        p.add(new JLabel("Fuzz Mode:"), lc(0, 0));
        p.add(modeRow, fcc);

        ButtonGroup bg = new ButtonGroup();
        bg.add(builtinRadio); bg.add(fileRadio);

        fileField.setEnabled(false);
        browseBtn.setEnabled(false);
        builtinRadio.addActionListener(e -> { fileField.setEnabled(false); browseBtn.setEnabled(false); });
        fileRadio.addActionListener(e   -> { fileField.setEnabled(true);  browseBtn.setEnabled(true);  });

        p.add(new JLabel("Wordlist:"), lc(0, 1));
        JPanel wlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        wlRow.add(builtinRadio); wlRow.add(fileRadio); wlRow.add(fileField); wlRow.add(browseBtn);
        p.add(wlRow, fc(1, 1, 3));

        p.add(new JLabel("Threads:"), lc(0, 2));
        p.add(threadsSpinner, fc(1, 2, 1));
        p.add(new JLabel("Delay (ms):"), lc(2, 2));
        p.add(delaySpinner, fc(3, 2, 1));

        p.add(new JLabel("Filter Codes:"), lc(0, 3));
        filterField.setToolTipText("Comma-separated status codes to keep. Empty = show all.");
        p.add(filterField, fc(1, 3, 1));
        p.add(followRedirCheck, fc(2, 3, 2));

        return p;
    }

    private JPanel buildResultsPanel() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(new TitledBorder("Results"));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        btnRow.add(startBtn); btnRow.add(stopBtn); btnRow.add(clearBtn); btnRow.add(exportBtn);
        stopBtn.setEnabled(false);
        progressBar.setStringPainted(true);

        JPanel statusRow = new JPanel(new BorderLayout(4, 0));
        statusRow.add(progressBar, BorderLayout.CENTER);
        statusRow.add(statusLabel, BorderLayout.EAST);

        JPanel top = new JPanel(new BorderLayout(0, 2));
        top.add(btnRow,    BorderLayout.NORTH);
        top.add(statusRow, BorderLayout.SOUTH);

        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(resultsTable), BorderLayout.CENTER);
        return p;
    }

    // -------------------------------------------------------------------------
    // Wiring
    // -------------------------------------------------------------------------
    private void wireActions() {
        browseBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                fileField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        startBtn.addActionListener(e  -> startFuzzing());
        stopBtn.addActionListener(e   -> stopFuzzing());
        clearBtn.addActionListener(e  -> {
            tableModel.clear();
            progressBar.setValue(0);
            statusLabel.setText("Ready");
        });
        exportBtn.addActionListener(e -> exportCsv());

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { if (e.isPopupTrigger()) showPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) showPopup(e); }
        });
    }

    private void showPopup(MouseEvent e) {
        int row = resultsTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        resultsTable.setRowSelectionInterval(row, row);
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copy = new JMenuItem("Copy Value");
        copy.addActionListener(ev -> {
            FuzzResult r = tableModel.getResult(resultsTable.convertRowIndexToModel(row));
            Toolkit.getDefaultToolkit().getSystemClipboard()
                   .setContents(new StringSelection(r.getValue()), null);
        });
        menu.add(copy);
        menu.show(resultsTable, e.getX(), e.getY());
    }

    // -------------------------------------------------------------------------
    // Fuzzing logic
    // -------------------------------------------------------------------------
    private void startFuzzing() {
        String rawUrl = urlField.getText().trim();
        if (rawUrl.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a target URL.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
            rawUrl = "http://" + rawUrl;
        }

        final URL targetUrl;
        try { targetUrl = new URL(rawUrl); }
        catch (MalformedURLException ex) {
            JOptionPane.showMessageDialog(this, "Invalid URL: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        boolean pairsMode   = pairsModeRadio.isSelected();
        String  headerName  = headerNameField.getText().trim();
        if (!pairsMode && headerName.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a header name.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<String> wordlist = loadWordlist("/wordlists/header-pairs.txt");
        if (wordlist.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Wordlist is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        Set<Integer> filterCodes = parseFilterCodes(filterField.getText().trim());
        int    threads      = (int) threadsSpinner.getValue();
        int    delay        = (int) delaySpinner.getValue();
        String method       = (String) methodCombo.getSelectedItem();
        String baseHdrText  = baseHeadersArea.getText().trim();
        String body         = bodyArea.getText();

        String host       = targetUrl.getHost();
        boolean useHttps  = "https".equalsIgnoreCase(targetUrl.getProtocol());
        int     port      = targetUrl.getPort();
        if (port == -1) port = useHttps ? 443 : 80;
        String path       = targetUrl.getPath().isEmpty() ? "/" : targetUrl.getPath();
        String query      = targetUrl.getQuery();
        if (query != null) path = path + "?" + query;

        final String finalHost = host;
        final int    finalPort = port;
        final boolean finalHttps = useHttps;
        final String finalPath = path;

        tableModel.clear();
        progressBar.setMaximum(wordlist.size());
        progressBar.setValue(0);
        statusLabel.setText("Starting…");
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        running.set(true);

        AtomicInteger completed   = new AtomicInteger(0);
        AtomicInteger interesting = new AtomicInteger(0);

        executor = Executors.newFixedThreadPool(threads);

        for (String wlEntry : wordlist) {
            if (!running.get()) break;
            final String entry = wlEntry;
            executor.submit(() -> {
                if (!running.get()) return;
                try {
                    if (delay > 0) Thread.sleep(delay);

                    // Build the injected header string
                    String injectedHeader;
                    String displayValue;
                    if (pairsMode) {
                        // entry is a full "Name: Value" pair
                        injectedHeader = entry;
                        displayValue   = entry;
                    } else {
                        injectedHeader = headerName + ": " + entry;
                        displayValue   = entry;
                    }

                    byte[] request;
                    if (baseRequestBytes != null) {
                        request = injectHeaderIntoRequest(baseRequestBytes, injectedHeader, !pairsMode ? headerName : null);
                    } else {
                        request = buildRequest(method, finalHost, finalPort, finalHttps,
                                               finalPath, baseHdrText, injectedHeader, body);
                    }

                    long   t0       = System.currentTimeMillis();
                    byte[] response = callbacks.makeHttpRequest(finalHost, finalPort, finalHttps, request);
                    long   elapsed  = System.currentTimeMillis() - t0;

                    int    status = 0;
                    int    length = 0;
                    String notes  = "";
                    if (response != null && response.length > 0) {
                        IResponseInfo ri = helpers.analyzeResponse(response);
                        status = ri.getStatusCode();
                        length = response.length - ri.getBodyOffset();
                        if (status >= 300 && status < 400) {
                            for (String h : ri.getHeaders()) {
                                if (h.toLowerCase().startsWith("location:")) {
                                    notes = h.trim(); break;
                                }
                            }
                        }
                    }

                    final int fs = status, fl = length;
                    final long ft = elapsed;
                    final String fv = displayValue, fn = notes;

                    if (filterCodes.isEmpty() || filterCodes.contains(fs)) {
                        final int idx = interesting.incrementAndGet();
                        SwingUtilities.invokeLater(() ->
                            tableModel.addResult(new FuzzResult(idx, fv, fs, fl, ft, fn)));
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                } catch (Exception ex) {
                    callbacks.printError("HeaderFuzzer error: " + ex.getMessage());
                } finally {
                    int done  = completed.incrementAndGet();
                    int total = wordlist.size();
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(done);
                        statusLabel.setText(done + "/" + total + " • " + interesting.get() + " results");
                        if (done >= total) onFuzzingComplete(total, interesting.get());
                    });
                }
            });
        }
        executor.shutdown();
    }

    private void stopFuzzing() {
        running.set(false);
        if (executor != null) executor.shutdownNow();
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        statusLabel.setText("Stopped");
    }

    private void onFuzzingComplete(int total, int hits) {
        running.set(false);
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        statusLabel.setText("Done – " + total + " tested, " + hits + " results");
    }

    // -------------------------------------------------------------------------
    // Request builders
    // -------------------------------------------------------------------------
    private byte[] buildRequest(String method, String host, int port, boolean useHttps,
                                String path, String baseHeaders, String injectedHeader, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host);
        if ((useHttps && port != 443) || (!useHttps && port != 80)) sb.append(":").append(port);
        sb.append("\r\n");
        sb.append("User-Agent: Mozilla/5.0 (PathBreaker Security Scanner)\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");
        if (!baseHeaders.isEmpty()) {
            for (String line : baseHeaders.split("\n")) {
                line = line.trim();
                if (!line.isEmpty()) sb.append(line).append("\r\n");
            }
        }
        sb.append(injectedHeader).append("\r\n");
        if (!body.isEmpty()) {
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            sb.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
            sb.append("\r\n").append(body);
        } else {
            sb.append("\r\n");
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Inject a header into an existing raw request.
     * If {@code replaceHeaderName} is non-null, any existing header with that name is replaced;
     * otherwise the new header is simply appended before the blank line.
     */
    private byte[] injectHeaderIntoRequest(byte[] original, String newHeader, String replaceHeaderName) {
        IRequestInfo info    = helpers.analyzeRequest(original);
        List<String>  hdrs   = new ArrayList<>(info.getHeaders());
        int           bodyOff = info.getBodyOffset();
        byte[]        body   = Arrays.copyOfRange(original, bodyOff, original.length);

        if (replaceHeaderName != null) {
            String lower = replaceHeaderName.toLowerCase();
            hdrs.removeIf(h -> h.toLowerCase().startsWith(lower + ":"));
        }
        hdrs.add(newHeader);

        StringBuilder sb = new StringBuilder();
        for (String h : hdrs) sb.append(h).append("\r\n");
        sb.append("\r\n");
        byte[] headerBytes = sb.toString().getBytes(StandardCharsets.UTF_8);

        byte[] result = new byte[headerBytes.length + body.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(body, 0, result, headerBytes.length, body.length);
        return result;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------
    private List<String> loadWordlist(String builtinResource) {
        List<String> lines = new ArrayList<>();
        try {
            InputStream src = builtinRadio.isSelected()
                ? getClass().getResourceAsStream(builtinResource)
                : new FileInputStream(fileField.getText().trim());
            if (src == null) { callbacks.printError("Built-in wordlist not found."); return lines; }
            try (BufferedReader br = new BufferedReader(new InputStreamReader(src, StandardCharsets.UTF_8))) {
                String l;
                while ((l = br.readLine()) != null) {
                    l = l.trim();
                    if (!l.isEmpty() && !l.startsWith("#")) lines.add(l);
                }
            }
        } catch (IOException e) {
            callbacks.printError("Error loading wordlist: " + e.getMessage());
        }
        return lines;
    }

    private Set<Integer> parseFilterCodes(String raw) {
        Set<Integer> set = new HashSet<>();
        if (raw.isEmpty()) return set;
        for (String tok : raw.split(",")) {
            tok = tok.trim();
            if (!tok.isEmpty()) {
                try { set.add(Integer.parseInt(tok)); }
                catch (NumberFormatException ignored) {}
            }
        }
        return set;
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("pathbreaker-header-results.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
            pw.println("#,Value,Status,Length,Time(ms),Notes");
            for (FuzzResult r : tableModel.getResults()) {
                pw.printf("%d,\"%s\",%d,%d,%d,\"%s\"%n",
                    r.getIndex(), r.getValue().replace("\"", "\"\""),
                    r.getStatusCode(), r.getResponseLength(), r.getResponseTime(),
                    r.getNotes().replace("\"", "\"\""));
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // -------------------------------------------------------------------------
    // GridBagConstraints helpers
    // -------------------------------------------------------------------------
    private GridBagConstraints lc(int x, int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x; c.gridy = y;
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private GridBagConstraints fc(int x, int y, int width) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x; c.gridy = y; c.gridwidth = width;
        c.insets = new Insets(3, 2, 3, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        return c;
    }
}
