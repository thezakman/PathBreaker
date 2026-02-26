package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
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
 * Path Fuzzer panel – appends or replaces the URL path with entries from a
 * wordlist and records each response.
 */
public class PathFuzzerPanel extends JPanel {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    private static final int MAX_THREADS   = 50;
    private static final int MAX_DELAY_MS  = 60_000;

    // -------------------------------------------------------------------------
    // Fields – UI controls
    // -------------------------------------------------------------------------
    private final JTextField urlField           = new JTextField(40);
    private final JComboBox<String> methodCombo = new JComboBox<>(new String[]{"GET","POST","HEAD","OPTIONS","PUT","PATCH","DELETE"});
    private final JTextArea headersArea         = new JTextArea(3, 40);
    private final JComboBox<String> modeCombo   = new JComboBox<>(new String[]{"Replace Path", "Append to Path"});

    private final JRadioButton builtinRadio  = new JRadioButton("Built-in", true);
    private final JRadioButton fileRadio     = new JRadioButton("File");
    private final JTextField   fileField     = new JTextField(28);
    private final JButton      browseBtn     = new JButton("Browse…");

    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(10, 1, MAX_THREADS, 1));
    private final JSpinner delaySpinner   = new JSpinner(new SpinnerNumberModel(0, 0, MAX_DELAY_MS, 100));
    private final JCheckBox followRedirCheck = new JCheckBox("Follow Redirects", false);
    private final JTextField filterField   = new JTextField("", 20);

    private final JButton startBtn  = new JButton("▶  Start");
    private final JButton stopBtn   = new JButton("■  Stop");
    private final JButton clearBtn  = new JButton("Clear");
    private final JButton exportBtn = new JButton("Export CSV");

    private final JProgressBar progressBar  = new JProgressBar();
    private final JLabel       statusLabel  = new JLabel("Ready");
    private final ResultsTableModel tableModel = new ResultsTableModel();
    private final JTable resultsTable;

    // -------------------------------------------------------------------------
    // Fields – runtime
    // -------------------------------------------------------------------------
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ExecutorService executor;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    public PathFuzzerPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers   = helpers;
        this.resultsTable = new JTable(tableModel);
        tableModel.applyTo(resultsTable);
        buildUI();
        wireActions();
    }

    // -------------------------------------------------------------------------
    // Public API used by BurpExtender context menu
    // -------------------------------------------------------------------------
    public void loadRequest(IHttpRequestResponse message) {
        if (message == null) return;
        var service = message.getHttpService();
        if (service == null) return;
        String proto = service.getProtocol();
        String host  = service.getHost();
        int    port  = service.getPort();
        boolean defaultPort = ("https".equals(proto) && port == 443)
                           || ("http".equals(proto)  && port == 80);
        String base = proto + "://" + host + (defaultPort ? "" : ":" + port) + "/";
        urlField.setText(base);
        SwingUtilities.invokeLater(() -> urlField.requestFocus());
    }

    // -------------------------------------------------------------------------
    // UI construction
    // -------------------------------------------------------------------------
    private void buildUI() {
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout(6, 6));
        top.add(buildTargetPanel(),   BorderLayout.NORTH);
        top.add(buildWordlistPanel(), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, buildResultsPanel());
        split.setDividerLocation(295);
        split.setResizeWeight(0.30);

        add(split, BorderLayout.CENTER);
    }

    private JPanel buildTargetPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Target Configuration"));
        GridBagConstraints lc = labelConstraints();
        GridBagConstraints fc = fieldConstraints();

        lc.gridy = 0; fc.gridy = 0;
        p.add(new JLabel("URL:"), lc);
        fc.gridwidth = 3;
        p.add(urlField, fc);
        fc.gridwidth = 1;

        lc.gridy = 1; fc.gridy = 1;
        p.add(new JLabel("Method:"), lc);
        p.add(methodCombo, fc);
        fc.gridx = 2;
        p.add(new JLabel("Mode:"), lc(2, 1));
        p.add(modeCombo, fc);

        lc.gridy = 2; fc.gridy = 2; fc.gridx = 1;
        p.add(new JLabel("Extra Headers:"), lc(0, 2));
        fc.gridwidth = 3;
        JScrollPane sp = new JScrollPane(headersArea);
        sp.setPreferredSize(new Dimension(400, 55));
        p.add(sp, fc);

        return p;
    }

    private JPanel buildWordlistPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new TitledBorder("Fuzzing Options"));

        ButtonGroup bg = new ButtonGroup();
        bg.add(builtinRadio);
        bg.add(fileRadio);

        fileField.setEnabled(false);
        browseBtn.setEnabled(false);
        builtinRadio.addActionListener(e -> { fileField.setEnabled(false); browseBtn.setEnabled(false); });
        fileRadio.addActionListener(e   -> { fileField.setEnabled(true);  browseBtn.setEnabled(true);  });

        int row = 0;
        p.add(new JLabel("Wordlist:"), lc(0, row));
        JPanel rp = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        rp.add(builtinRadio); rp.add(fileRadio); rp.add(fileField); rp.add(browseBtn);
        GridBagConstraints fc = fieldConstraints();
        fc.gridy = row; fc.gridwidth = 3;
        p.add(rp, fc);

        row++;
        p.add(new JLabel("Threads:"), lc(0, row));
        fc = fieldConstraints(); fc.gridy = row;
        p.add(threadsSpinner, fc);
        p.add(new JLabel("Delay (ms):"), lc(2, row));
        fc = fieldConstraints(); fc.gridy = row; fc.gridx = 3;
        p.add(delaySpinner, fc);

        row++;
        p.add(new JLabel("Filter Codes:"), lc(0, row));
        fc = fieldConstraints(); fc.gridy = row;
        filterField.setToolTipText("Comma-separated status codes to keep, e.g. 200,301,302. Leave empty to show all.");
        p.add(filterField, fc);
        fc = fieldConstraints(); fc.gridy = row; fc.gridx = 2;
        p.add(followRedirCheck, fc);

        return p;
    }

    private JPanel buildResultsPanel() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(new TitledBorder("Results"));

        // Button row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        btnRow.add(startBtn);
        btnRow.add(stopBtn);
        btnRow.add(clearBtn);
        btnRow.add(exportBtn);
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

        startBtn.addActionListener(e -> startFuzzing());
        stopBtn.addActionListener(e  -> stopFuzzing());
        clearBtn.addActionListener(e -> {
            tableModel.clear();
            progressBar.setValue(0);
            statusLabel.setText("Ready");
        });
        exportBtn.addActionListener(e -> exportCsv());

        // Right-click on results → copy URL
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showTablePopup(e);
            }
            @Override public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showTablePopup(e);
            }
        });
    }

    private void showTablePopup(MouseEvent e) {
        int row = resultsTable.rowAtPoint(e.getPoint());
        if (row < 0) return;
        resultsTable.setRowSelectionInterval(row, row);
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy URL");
        copyItem.addActionListener(ev -> {
            FuzzResult r = tableModel.getResult(resultsTable.convertRowIndexToModel(row));
            Toolkit.getDefaultToolkit().getSystemClipboard()
                   .setContents(new StringSelection(buildFullUrl(r.getValue())), null);
        });
        menu.add(copyItem);
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
        try {
            targetUrl = new URL(rawUrl);
        } catch (MalformedURLException ex) {
            JOptionPane.showMessageDialog(this, "Invalid URL: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<String> paths = loadWordlist("/wordlists/paths.txt");
        if (paths.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Wordlist is empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        Set<Integer> filterCodes = parseFilterCodes(filterField.getText().trim());
        int threads = (int) threadsSpinner.getValue();
        int delay   = (int) delaySpinner.getValue();
        String method = (String) methodCombo.getSelectedItem();
        String extraHeaders = headersArea.getText().trim();
        boolean appendMode = "Append to Path".equals(modeCombo.getSelectedItem());

        tableModel.clear();
        progressBar.setMaximum(paths.size());
        progressBar.setValue(0);
        statusLabel.setText("Starting…");
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        running.set(true);

        AtomicInteger completed = new AtomicInteger(0);
        AtomicInteger interesting = new AtomicInteger(0);

        executor = Executors.newFixedThreadPool(threads);

        for (String pathEntry : paths) {
            if (!running.get()) break;
            final String entry = pathEntry;
            executor.submit(() -> {
                if (!running.get()) return;
                try {
                    if (delay > 0) Thread.sleep(delay);

                    String host      = targetUrl.getHost();
                    boolean useHttps = "https".equalsIgnoreCase(targetUrl.getProtocol());
                    int port         = targetUrl.getPort();
                    if (port == -1) port = useHttps ? 443 : 80;

                    String fuzzedPath;
                    if (appendMode) {
                        String base = targetUrl.getPath();
                        if (!base.endsWith("/")) base = base + "/";
                        fuzzedPath = base + (entry.startsWith("/") ? entry.substring(1) : entry);
                    } else {
                        fuzzedPath = entry.startsWith("/") ? entry : "/" + entry;
                    }

                    byte[] request  = buildGetRequest(method, host, port, useHttps, fuzzedPath, extraHeaders);
                    long   t0       = System.currentTimeMillis();
                    byte[] response = callbacks.makeHttpRequest(host, port, useHttps, request);
                    long   elapsed  = System.currentTimeMillis() - t0;

                    int status = 0;
                    int length = 0;
                    String notes = "";
                    if (response != null && response.length > 0) {
                        IResponseInfo ri = helpers.analyzeResponse(response);
                        status = ri.getStatusCode();
                        length = response.length - ri.getBodyOffset();
                        if (status >= 300 && status < 400) {
                            for (String hdr : ri.getHeaders()) {
                                if (hdr.toLowerCase().startsWith("location:")) {
                                    notes = hdr.trim();
                                    break;
                                }
                            }
                        }
                    }

                    final int fs = status, fl = length;
                    final long ft = elapsed;
                    final String fn = notes;

                    if (filterCodes.isEmpty() || filterCodes.contains(fs)) {
                        final int idx = interesting.incrementAndGet();
                        SwingUtilities.invokeLater(() ->
                            tableModel.addResult(new FuzzResult(idx, fuzzedPath, fs, fl, ft, fn)));
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                } catch (Exception ex) {
                    callbacks.printError("PathFuzzer error: " + ex.getMessage());
                } finally {
                    int done = completed.incrementAndGet();
                    int total = paths.size();
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
    // Helpers
    // -------------------------------------------------------------------------
    private byte[] buildGetRequest(String method, String host, int port,
                                   boolean useHttps, String path, String extraHeaders) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host);
        if ((useHttps && port != 443) || (!useHttps && port != 80)) {
            sb.append(":").append(port);
        }
        sb.append("\r\n");
        sb.append("User-Agent: Mozilla/5.0 (PathBreaker Security Scanner)\r\n");
        sb.append("Accept: */*\r\n");
        sb.append("Connection: close\r\n");
        if (!extraHeaders.isEmpty()) {
            for (String line : extraHeaders.split("\n")) {
                line = line.trim();
                if (!line.isEmpty()) sb.append(line).append("\r\n");
            }
        }
        sb.append("\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String buildFullUrl(String path) {
        String base = urlField.getText().trim();
        try {
            URL u = new URL(base.startsWith("http") ? base : "http://" + base);
            String root = u.getProtocol() + "://" + u.getHost()
                        + (u.getPort() == -1 ? "" : ":" + u.getPort());
            return root + (path.startsWith("/") ? path : "/" + path);
        } catch (MalformedURLException e) {
            return path;
        }
    }

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
        fc.setSelectedFile(new File("pathbreaker-results.csv"));
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
    private GridBagConstraints labelConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = 0;
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private GridBagConstraints fieldConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 1; c.gridy = 0;
        c.insets = new Insets(3, 2, 3, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        return c;
    }

    private GridBagConstraints lc(int x, int y) {
        GridBagConstraints c = labelConstraints();
        c.gridx = x; c.gridy = y;
        return c;
    }
}
