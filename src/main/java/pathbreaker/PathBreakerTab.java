package pathbreaker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IHttpService;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public class PathBreakerTab implements IMessageEditorController {

    // Dark-theme colors
    private static final Color BG = new Color(0x1e1e1e);
    private static final Color BG_MID = new Color(0x252526);
    private static final Color BG_LIGHT = new Color(0x2d2d30);
    private static final Color FG = new Color(0xd4d4d4);
    private static final Color GREEN = new Color(0x00FF41);
    private static final Color CYAN = new Color(0x00CFFF);
    private static final Color RED = new Color(0xFF4444);
    private static final Color ORANGE = new Color(0xFFA500);
    private static final Color YELLOW = new Color(0xFFFF00);
    private static final Color GRAY = new Color(0x888888);
    private static final Color ACCENT = new Color(0x007ACC);

    private final MontoyaApi api;
    private final JPanel mainPanel;

    // Config controls
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private JComboBox<String> injectModeBox;
    private JComboBox<String> fuzzTargetBox;
    private JCheckBox permuteHeadersBox;
    private JSpinner threadsSpinner;
    private JCheckBox onlyHitsBox;
    private JCheckBox hideErrorsBox;
    private JCheckBox programmaticBox;
    private JTextField filterCodesField;
    private JButton actionBtn;
    private JButton clearBtn;

    // Header defs
    private static final String[][] HEADER_DEFS = {
            { "Referer", "" },
            { "X-Forwarded-For", "127.0.0.1" },
            { "X-Real-IP", "127.0.0.1" },
            { "X-Forwarded-Host", "localhost" },
            { "X-Original-URL", "/" },
            { "X-Rewrite-URL", "/" },
            { "X-Custom-IP-Authorization", "127.0.0.1" },
            { "Origin", "null" },
            { "X-Host", "localhost" },
            { "True-Client-IP", "127.0.0.1" },
    };
    private JTable headersTable;
    private DefaultTableModel headersTableModel;
    private JPanel headersPanel;

    // Payloads
    private JTable payloadsTable;
    private DefaultTableModel payloadsTableModel;
    private JPanel payloadsPanel;

    // Results table
    private DefaultTableModel tableModel;
    private JTable resultsTable;
    private TableRowSorter<DefaultTableModel> rowSorter;
    private final List<FuzzResult> results = new ArrayList<>();

    // Detail panels
    // Progress
    private JProgressBar progressBar;
    private JLabel statusLabel;

    // State
    private HttpRequestResponse currentTarget;
    private volatile ExecutorService activeExecutor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger tested = new AtomicInteger(0);
    private final AtomicInteger hits = new AtomicInteger(0);
    private volatile int totalCount = 0;

    public PathBreakerTab(MontoyaApi api) {
        this.api = api;
        mainPanel = buildUI();
    }

    public JPanel getComponent() {
        return mainPanel;
    }

    public void setTarget(HttpRequestResponse reqResp) {
        this.currentTarget = reqResp;
        SwingUtilities.invokeLater(() -> {
            String urlStr = reqResp.request().url();
            if (requestEditor != null) {
                requestEditor.setMessage(reqResp.request().toByteArray().getBytes(), true);
            }
            if (responseEditor != null) {
                if (reqResp.response() != null) {
                    responseEditor.setMessage(reqResp.response().toByteArray().getBytes(), false);
                } else {
                    responseEditor.setMessage(new byte[0], false);
                }
            }
            for (int i = 0; i < headersTableModel.getRowCount(); i++) {
                if ("Referer".equals(headersTableModel.getValueAt(i, 1))) {
                    headersTableModel.setValueAt(urlStr, i, 2);
                    break;
                }
            }
        });
    }

    // ────────────────────────────────────────────────────────────────────────
    // UI Construction
    // ────────────────────────────────────────────────────────────────────────

    private JPanel buildUI() {
        JPanel panel = new JPanel(new BorderLayout(0, 0));
        panel.setBackground(BG);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setBackground(BG);
        tabbedPane.setForeground(FG);

        // Fuzzer Tab
        JPanel fuzzerTab = new JPanel(new BorderLayout(0, 0));
        fuzzerTab.setBackground(BG);
        fuzzerTab.add(buildNorthBar(), BorderLayout.NORTH);
        fuzzerTab.add(buildCenterSplit(), BorderLayout.CENTER);
        fuzzerTab.add(buildSouthBar(), BorderLayout.SOUTH);

        tabbedPane.addTab("Fuzzer", fuzzerTab);

        // Headers Tab
        JPanel headersTab = new JPanel(new BorderLayout());
        headersTab.setBackground(BG_LIGHT);
        headersTab.add(headersPanel, BorderLayout.CENTER);

        tabbedPane.addTab("Headers", headersTab);

        // Payloads Tab
        buildPayloadsTab();
        JPanel payloadsTab = new JPanel(new BorderLayout());
        payloadsTab.setBackground(BG_LIGHT);
        payloadsTab.add(payloadsPanel, BorderLayout.CENTER);

        tabbedPane.addTab("Payloads", payloadsTab);

        tabbedPane.addTab("About", buildAboutTab());

        panel.add(tabbedPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildAboutTab() {
        JPanel about = new JPanel(new GridBagLayout()); // Use GridBagLayout to center the content
        about.setBackground(BG_LIGHT);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(BG_LIGHT);
        content.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Load logo
        try {
            java.net.URL imgURL = getClass().getResource("/pathbreaker/PathBreaker.png");
            if (imgURL != null) {
                ImageIcon originalIcon = new ImageIcon(imgURL);
                Image img = originalIcon.getImage();
                // Resize if needed, adjust to reasonable width like 200px while maintaining
                // aspect ratio
                int newWidth = 512;
                int newHeight = (int) ((double) originalIcon.getIconHeight() / originalIcon.getIconWidth() * newWidth);
                Image resizedImg = img.getScaledInstance(newWidth, newHeight, Image.SCALE_SMOOTH);
                JLabel logoLabel = new JLabel(new ImageIcon(resizedImg));
                logoLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
                logoLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 15, 0));
                content.add(logoLabel);
            }
        } catch (Exception ex) {
            // If image fails to load, just ignore
        }

        JLabel title = styled(new JLabel("PathBreaker v1.4"), ACCENT);
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 18));
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel desc = styled(new JLabel("A professional path and header fuzzing extension for Burp Suite."), FG);
        desc.setAlignmentX(Component.CENTER_ALIGNMENT);
        desc.setBorder(BorderFactory.createEmptyBorder(10, 0, 15, 0));

        JButton ghBtn = makeButton("GitHub Repository: @thezakman", BG_MID, FG);
        ghBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        ghBtn.addActionListener(e -> {
            try {
                Desktop.getDesktop().browse(new java.net.URI("https://github.com/thezakman/"));
            } catch (Exception ex) {
                // ignore
            }
        });

        content.add(title);
        content.add(desc);
        content.add(ghBtn);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.CENTER;
        about.add(content, gbc);

        return about;
    }

    private JPanel buildNorthBar() {
        JPanel bar = new JPanel();
        bar.setLayout(new BoxLayout(bar, BoxLayout.Y_AXIS));
        bar.setBackground(BG_LIGHT);
        bar.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // Row 1: controls (now at the top)
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row1.setBackground(BG_LIGHT);

        actionBtn = makeButton("▶ Start", ACCENT, Color.WHITE);
        clearBtn = makeButton("Clear", BG_MID, FG);

        actionBtn.addActionListener(e -> {
            if (running.get())
                stopFuzz();
            else
                startFuzz();
        });
        clearBtn.addActionListener(e -> clearResults());

        row1.add(actionBtn);
        row1.add(clearBtn);

        row1.add(styled(new JLabel("Mode:"), FG));
        injectModeBox = new JComboBox<>(new String[] { "tail", "prefix", "mid:1", "replace" });
        styleCombo(injectModeBox);
        row1.add(injectModeBox);

        row1.add(styled(new JLabel("Fuzz:"), FG));
        fuzzTargetBox = new JComboBox<>(new String[] { "Paths", "Headers", "Both" });
        fuzzTargetBox.setSelectedItem("Both");
        styleCombo(fuzzTargetBox);
        row1.add(fuzzTargetBox);

        row1.add(styled(new JLabel("Threads:"), FG));
        threadsSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 50, 1));
        styleSpinner(threadsSpinner);
        row1.add(threadsSpinner);

        onlyHitsBox = styleCheck(new JCheckBox("Only Hits"));
        onlyHitsBox.addActionListener(e -> applyFilters());
        row1.add(onlyHitsBox);

        hideErrorsBox = styleCheck(new JCheckBox("Hide Errors"));
        hideErrorsBox.addActionListener(e -> applyFilters());
        row1.add(hideErrorsBox);

        programmaticBox = styleCheck(new JCheckBox("Programmatic"));
        programmaticBox.setSelected(true);
        row1.add(programmaticBox);

        row1.add(styled(new JLabel("Filter codes:"), FG));
        filterCodesField = new JTextField(10);
        styleTextField(filterCodesField);
        filterCodesField.setToolTipText("e.g. 200,302");
        filterCodesField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                applyFilters();
            }
        });
        row1.add(filterCodesField);

        // Headers Panel
        headersPanel = new JPanel(new BorderLayout());
        headersPanel.setBackground(BG_LIGHT);
        headersPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel wbtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        wbtnRow.setBackground(BG_LIGHT);
        JLabel wlbl = styled(new JLabel("Headers: "), FG);
        wlbl.setFont(wlbl.getFont().deriveFont(Font.BOLD));

        JButton addBtn = makeButton("+ Add Row", GREEN.darker().darker(), FG);
        JButton remBtn = makeButton("- Remove Selected", RED.darker().darker(), FG);
        JButton clearBtnHeaders = makeButton("Clear All", BG_MID, FG);
        JButton restoreBtn = makeButton("Restore Default", BG_MID, FG);
        JButton loadBtn = makeButton("Load File...", ACCENT, Color.WHITE);
        JButton allOnBtn = makeButton("All On", BG_MID, FG);
        JButton allOffBtn = makeButton("All Off", BG_MID, FG);

        permuteHeadersBox = styleCheck(new JCheckBox("Permute individually"));
        permuteHeadersBox.setSelected(true);

        wbtnRow.add(wlbl);
        wbtnRow.add(addBtn);
        wbtnRow.add(remBtn);
        wbtnRow.add(clearBtnHeaders);
        wbtnRow.add(restoreBtn);
        wbtnRow.add(loadBtn);
        wbtnRow.add(allOnBtn);
        wbtnRow.add(allOffBtn);
        wbtnRow.add(Box.createHorizontalStrut(15));
        wbtnRow.add(permuteHeadersBox);
        headersPanel.add(wbtnRow, BorderLayout.NORTH);

        headersTableModel = new DefaultTableModel(new String[] { "Enabled", "Header Name", "Value" }, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
        };

        for (String[] def : HEADER_DEFS) {
            headersTableModel.addRow(new Object[] { false, def[0], def[1] });
        }

        headersTable = new JTable(headersTableModel);
        headersTable.setBackground(BG_MID);
        headersTable.setForeground(FG);
        headersTable.setGridColor(BG_LIGHT);
        headersTable.setSelectionBackground(ACCENT);
        headersTable.setSelectionForeground(Color.WHITE);
        headersTable.setRowHeight(24);
        headersTable.getTableHeader().setBackground(BG_LIGHT);
        headersTable.getTableHeader().setForeground(FG);

        headersTable.getColumnModel().getColumn(0).setMaxWidth(60);

        JScrollPane hScroll = new JScrollPane(headersTable);
        hScroll.setBackground(BG_MID);
        hScroll.getViewport().setBackground(BG_MID);
        hScroll.setBorder(BorderFactory.createLineBorder(BG_LIGHT));
        headersPanel.add(hScroll, BorderLayout.CENTER);

        addBtn.addActionListener(e -> headersTableModel.addRow(new Object[] { true, "New-Header", "Value" }));
        remBtn.addActionListener(e -> {
            int[] selected = headersTable.getSelectedRows();
            for (int i = selected.length - 1; i >= 0; i--) {
                headersTableModel.removeRow(headersTable.convertRowIndexToModel(selected[i]));
            }
        });
        clearBtnHeaders.addActionListener(e -> headersTableModel.setRowCount(0));
        restoreBtn.addActionListener(e -> {
            headersTableModel.setRowCount(0);
            for (String[] def : HEADER_DEFS) {
                headersTableModel.addRow(new Object[] { false, def[0], def[1] });
            }
        });
        allOnBtn.addActionListener(e -> {
            for (int i = 0; i < headersTableModel.getRowCount(); i++)
                headersTableModel.setValueAt(true, i, 0);
        });
        allOffBtn.addActionListener(e -> {
            for (int i = 0; i < headersTableModel.getRowCount(); i++)
                headersTableModel.setValueAt(false, i, 0);
        });
        loadBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            int result = chooser.showOpenDialog(mainPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                java.io.File file = chooser.getSelectedFile();
                loadBtn.setText("Loading...");
                loadBtn.setEnabled(false);

                new Thread(() -> {
                    try {
                        java.util.List<String> lines = java.nio.file.Files.readAllLines(file.toPath(),
                                java.nio.charset.StandardCharsets.UTF_8);
                        java.util.List<Object[]> rowsToAdd = new java.util.ArrayList<>();
                        for (String line : lines) {
                            line = line.trim();
                            if (!line.isEmpty() && !line.startsWith("#")) {
                                int colonIdx = line.indexOf(':');
                                if (colonIdx > 0) {
                                    String hName = line.substring(0, colonIdx).trim();
                                    String hVal = line.substring(colonIdx + 1).trim();
                                    rowsToAdd.add(new Object[] { true, hName, hVal });
                                }
                            }
                        }
                        SwingUtilities.invokeLater(() -> {
                            for (Object[] row : rowsToAdd) {
                                headersTableModel.addRow(row);
                            }
                            loadBtn.setText("Load File...");
                            loadBtn.setEnabled(true);
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(mainPanel, "Error loading file: " + ex.getMessage(), "Error",
                                    JOptionPane.ERROR_MESSAGE);
                            loadBtn.setText("Load File...");
                            loadBtn.setEnabled(true);
                        });
                    }
                }).start();
            }
        });

        bar.add(row1);
        return bar;
    }

    private JPanel detailPanel(String title, Component area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(BG_MID);
        JPanel titleBar = new JPanel(new BorderLayout());
        titleBar.setBackground(new Color(0x3c3c3c));
        titleBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BG));

        JPanel leftFlow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        leftFlow.setOpaque(false);
        JLabel lbl = new JLabel(title);
        lbl.setForeground(FG);
        lbl.setFont(lbl.getFont().deriveFont(Font.BOLD, 12f));
        leftFlow.add(lbl);
        titleBar.add(leftFlow, BorderLayout.WEST);

        p.add(titleBar, BorderLayout.NORTH);
        p.add(area, BorderLayout.CENTER);
        return p;
    }

    private JSplitPane buildCenterSplit() {
        // ── Upper: results table ──
        String[] cols = { "#", "Status", "Length", "Payload Path", "Label", "Notes" };
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return c == 5; // Allow editing only the Notes column
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 1 || columnIndex == 2) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        tableModel.addTableModelListener(e -> {
            if (e.getType() == javax.swing.event.TableModelEvent.UPDATE) {
                int row = e.getFirstRow();
                int column = e.getColumn();
                if (column == 5 && row >= 0 && row < resultsTable.getRowCount()) {
                    int modelRow = resultsTable.convertRowIndexToModel(row);
                    if (modelRow >= 0 && modelRow < results.size()) {
                        String newNote = (String) tableModel.getValueAt(modelRow, column);
                        results.get(modelRow).note = newNote != null ? newNote : "";
                    }
                }
            }
        });

        resultsTable = new JTable(tableModel);
        resultsTable.setBackground(BG_MID);
        resultsTable.setForeground(FG);
        resultsTable.setGridColor(BG_LIGHT);
        resultsTable.setSelectionBackground(ACCENT);
        resultsTable.setSelectionForeground(Color.WHITE);
        resultsTable.setRowHeight(20);
        resultsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        resultsTable.getTableHeader().setBackground(BG_LIGHT);
        resultsTable.getTableHeader().setForeground(FG);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        rowSorter = new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(rowSorter);

        // Column widths
        int[] widths = { 45, 60, 70, 380, 200, 200 };
        for (int i = 0; i < widths.length; i++) {
            resultsTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }

        // Color renderer
        StatusCellRenderer renderer = new StatusCellRenderer();
        for (int i = 0; i < cols.length; i++) {
            resultsTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting())
                onRowSelected();
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setBackground(BG_MID);
        tableScroll.getViewport().setBackground(BG_MID);
        tableScroll.setBorder(BorderFactory.createLineBorder(BG_LIGHT));

        // ── Top: side-by-side Request/Response ──
        if (PathBreakerExtension.legacyCallbacks != null) {
            requestEditor = PathBreakerExtension.legacyCallbacks.createMessageEditor(this, false);
            responseEditor = PathBreakerExtension.legacyCallbacks.createMessageEditor(this, false);
        }

        JPanel reqPanel = detailPanel("Request", requestEditor != null ? requestEditor.getComponent() : new JPanel());
        JPanel respPanel = detailPanel("Response",
                responseEditor != null ? responseEditor.getComponent() : new JPanel());

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        topSplit.setResizeWeight(0.5);
        topSplit.setDividerSize(5);
        topSplit.setBackground(BG);
        topSplit.setBorder(null);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, tableScroll);
        split.setResizeWeight(0.4);
        split.setDividerSize(5);
        split.setBackground(BG);
        split.setBorder(null);
        return split;
    }

    private JPanel buildSouthBar() {
        JPanel bar = new JPanel(new BorderLayout(8, 0));
        bar.setBackground(BG_LIGHT);
        bar.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressBar.setBackground(BG_MID);
        progressBar.setForeground(ACCENT);

        statusLabel = styled(new JLabel("Idle"), GRAY);

        bar.add(progressBar, BorderLayout.CENTER);
        bar.add(statusLabel, BorderLayout.EAST);
        return bar;
    }

    private void buildPayloadsTab() {
        payloadsPanel = new JPanel(new BorderLayout());
        payloadsPanel.setBackground(BG_LIGHT);
        payloadsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel wbtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        wbtnRow.setBackground(BG_LIGHT);
        JLabel wlbl = styled(new JLabel("Payloads: "), FG);
        wlbl.setFont(wlbl.getFont().deriveFont(Font.BOLD));

        JButton addBtn = makeButton("+ Add Row", GREEN.darker().darker(), FG);
        JButton remBtn = makeButton("- Remove Selected", RED.darker().darker(), FG);
        JButton clearBtnPayloads = makeButton("Clear All", BG_MID, FG);
        JButton restoreBtn = makeButton("Restore Default", BG_MID, FG);
        JButton loadBtn = makeButton("Load File...", ACCENT, Color.WHITE);
        JButton allOnBtn = makeButton("All On", BG_MID, FG);
        JButton allOffBtn = makeButton("All Off", BG_MID, FG);

        wbtnRow.add(wlbl);
        wbtnRow.add(addBtn);
        wbtnRow.add(remBtn);
        wbtnRow.add(clearBtnPayloads);
        wbtnRow.add(restoreBtn);
        wbtnRow.add(loadBtn);
        wbtnRow.add(allOnBtn);
        wbtnRow.add(allOffBtn);
        payloadsPanel.add(wbtnRow, BorderLayout.NORTH);

        payloadsTableModel = new DefaultTableModel(new String[] { "Enabled", "Payload" }, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
        };

        // Populate builtin wordlist
        String[] builtinPayloads = FuzzEngine.BUILTIN_WORDLIST.split("\n");
        for (String payload : builtinPayloads) {
            if (!payload.trim().isEmpty()) {
                payloadsTableModel.addRow(new Object[] { true, payload });
            }
        }

        payloadsTable = new JTable(payloadsTableModel);
        payloadsTable.setBackground(BG_MID);
        payloadsTable.setForeground(FG);
        payloadsTable.setGridColor(BG_LIGHT);
        payloadsTable.setSelectionBackground(ACCENT);
        payloadsTable.setSelectionForeground(Color.WHITE);
        payloadsTable.setRowHeight(24);
        payloadsTable.getTableHeader().setBackground(BG_LIGHT);
        payloadsTable.getTableHeader().setForeground(FG);

        payloadsTable.getColumnModel().getColumn(0).setMaxWidth(60);

        JScrollPane hScroll = new JScrollPane(payloadsTable);
        hScroll.setBackground(BG_MID);
        hScroll.getViewport().setBackground(BG_MID);
        hScroll.setBorder(BorderFactory.createLineBorder(BG_LIGHT));
        payloadsPanel.add(hScroll, BorderLayout.CENTER);

        addBtn.addActionListener(e -> payloadsTableModel.addRow(new Object[] { true, "New-Payload" }));
        remBtn.addActionListener(e -> {
            int[] selected = payloadsTable.getSelectedRows();
            for (int i = selected.length - 1; i >= 0; i--) {
                payloadsTableModel.removeRow(payloadsTable.convertRowIndexToModel(selected[i]));
            }
        });
        clearBtnPayloads.addActionListener(e -> payloadsTableModel.setRowCount(0));
        restoreBtn.addActionListener(e -> {
            payloadsTableModel.setRowCount(0);
            String[] defaultPayloads = FuzzEngine.BUILTIN_WORDLIST.split("\n");
            for (String payload : defaultPayloads) {
                if (!payload.trim().isEmpty()) {
                    payloadsTableModel.addRow(new Object[] { true, payload.trim() });
                }
            }
        });
        allOnBtn.addActionListener(e -> {
            for (int i = 0; i < payloadsTableModel.getRowCount(); i++)
                payloadsTableModel.setValueAt(true, i, 0);
        });
        allOffBtn.addActionListener(e -> {
            for (int i = 0; i < payloadsTableModel.getRowCount(); i++)
                payloadsTableModel.setValueAt(false, i, 0);
        });
        loadBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            int result = chooser.showOpenDialog(mainPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                java.io.File file = chooser.getSelectedFile();
                loadBtn.setText("Loading...");
                loadBtn.setEnabled(false);

                new Thread(() -> {
                    try {
                        java.util.List<String> lines = java.nio.file.Files.readAllLines(file.toPath(),
                                java.nio.charset.StandardCharsets.UTF_8);
                        java.util.List<Object[]> rowsToAdd = new java.util.ArrayList<>();
                        for (String line : lines) {
                            if (!line.trim().isEmpty()) {
                                rowsToAdd.add(new Object[] { true, line.trim() });
                            }
                        }
                        SwingUtilities.invokeLater(() -> {
                            for (Object[] row : rowsToAdd) {
                                payloadsTableModel.addRow(row);
                            }
                            loadBtn.setText("Load File...");
                            loadBtn.setEnabled(true);
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(mainPanel, "Error loading file: " + ex.getMessage(), "Error",
                                    JOptionPane.ERROR_MESSAGE);
                            loadBtn.setText("Load File...");
                            loadBtn.setEnabled(true);
                        });
                    }
                }).start();
            }
        });
    }

    // ────────────────────────────────────────────────────────────────────────
    // Actions
    // ────────────────────────────────────────────────────────────────────────

    private void applyFilters() {
        if (rowSorter == null)
            return;
        RowFilter<DefaultTableModel, Integer> filter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                int modelRow = entry.getIdentifier();
                if (modelRow < 0 || modelRow >= results.size())
                    return false;
                FuzzResult r = results.get(modelRow);

                if (onlyHitsBox.isSelected() && !r.isInteresting)
                    return false;
                if (hideErrorsBox.isSelected() && r.statusCode == null)
                    return false;

                String f = filterCodesField.getText().trim();
                if (!f.isEmpty()) {
                    java.util.Set<Integer> parsed = new java.util.HashSet<>();
                    for (String s : f.split(",")) {
                        try {
                            parsed.add(Integer.parseInt(s.trim()));
                        } catch (Exception ignored) {
                        }
                    }
                    if (!parsed.isEmpty() && !parsed.contains(r.statusCode))
                        return false;
                }
                return true;
            }
        };
        rowSorter.setRowFilter(filter);
    }

    private void setUIEnabled(boolean enabled) {
        injectModeBox.setEnabled(enabled);
        fuzzTargetBox.setEnabled(enabled);
        threadsSpinner.setEnabled(enabled);
        permuteHeadersBox.setEnabled(enabled);
        onlyHitsBox.setEnabled(enabled);
        hideErrorsBox.setEnabled(enabled);
        programmaticBox.setEnabled(enabled);
        filterCodesField.setEnabled(enabled);

        // Disable the load/clear buttons to guard wordlists during execution
        for (Component c : headersPanel.getComponents()) {
            if (c instanceof JPanel) {
                for (Component sub : ((JPanel) c).getComponents()) {
                    if (sub instanceof JButton)
                        sub.setEnabled(enabled);
                }
            }
        }
        for (Component c : payloadsPanel.getComponents()) {
            if (c instanceof JPanel) {
                for (Component sub : ((JPanel) c).getComponents()) {
                    if (sub instanceof JButton)
                        sub.setEnabled(enabled);
                }
            }
        }
    }

    private void startFuzz() {
        if (currentTarget == null || requestEditor.getMessage() == null || requestEditor.getMessage().length == 0) {
            JOptionPane.showMessageDialog(mainPanel,
                    "No target set or base request is empty.\nRight-click a request in Proxy/Repeater → Send to PathBreaker.",
                    "PathBreaker", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String baseRequestRaw = new String(requestEditor.getMessage(), java.nio.charset.StandardCharsets.UTF_8);

        // Extract base path from request
        String basePath = "/";
        int firstLineEnd = baseRequestRaw.indexOf("\r\n");
        if (firstLineEnd > 0) {
            String firstLine = baseRequestRaw.substring(0, firstLineEnd);
            String[] parts = firstLine.split(" ");
            if (parts.length >= 2) {
                basePath = parts[1];
            }
        }

        if (running.get())
            return;

        running.set(true);
        tested.set(0);
        hits.set(0);
        totalCount = 0;

        actionBtn.setText("⏹ Stop");
        actionBtn.setBackground(new Color(0x8B0000));
        progressBar.setValue(0);
        progressBar.setString("Starting...");
        statusLabel.setText("Running...");

        setUIEnabled(false);

        FuzzConfig config = buildConfig();

        // Calculate total for progress
        List<String> wl = config.customWordlist;

        String bp = basePath;
        int q = bp.indexOf('?');
        if (q >= 0)
            bp = bp.substring(0, q);

        int pathCount;
        if ("Headers".equals(config.fuzzTarget)) {
            pathCount = 1;
        } else {
            pathCount = FuzzEngine.buildPaths(bp, wl, config.injectMode).size();
            if (config.useProgrammatic)
                pathCount += FuzzEngine.generateProgrammatic(bp).size();
        }

        int headerCount = 1;
        if ("Paths".equals(config.fuzzTarget)) {
            headerCount = 1;
        } else {
            headerCount = 1; // baseline
            if (!config.extraHeaders.isEmpty()) {
                if (config.permuteHeaders) {
                    headerCount += config.extraHeaders.size();
                } else {
                    headerCount += 1;
                }
            }
        }

        totalCount = pathCount * headerCount;
        final int total = totalCount;
        progressBar.setMaximum(Math.max(total, 1));
        progressBar.setString("0 / " + total + " — 0 hits");

        burp.api.montoya.http.HttpService targetService = currentTarget.request().httpService();
        burp.api.montoya.http.HttpService safeService = burp.api.montoya.http.HttpService.httpService(
                targetService.host(), targetService.port(), targetService.secure());

        activeExecutor = FuzzEngine.runFuzz(api, safeService, baseRequestRaw, config,
                result -> {
                    if (!running.get())
                        return; // hard stop
                    addResult(result);
                    int t = tested.incrementAndGet();
                    if (result.isInteresting) {
                        hits.incrementAndGet();
                        if (result.reqResp != null && result.statusCode != null && result.statusCode == 200) {
                            AuditIssue issue = AuditIssue.auditIssue(
                                    "PathBreaker Fuzz Hits",
                                    "PathBreaker discovered a potentially interesting response (" + result.statusCode
                                            + ") at: <b>" + result.rawPath + "</b><br><br>Payload Label: <b>"
                                            + result.label + "</b>",
                                    "Review the endpoints and ensure proper authorization and access controls are enforced.",
                                    currentTarget.request().url(),
                                    AuditIssueSeverity.INFORMATION,
                                    AuditIssueConfidence.FIRM,
                                    "N/A", // background
                                    "N/A", // remediation
                                    AuditIssueSeverity.INFORMATION,
                                    result.reqResp);
                            api.siteMap().add(issue);
                        }
                    }
                    int h = hits.get();
                    progressBar.setValue(t);
                    progressBar.setString(t + " / " + total + " tested — " + h + " hits");
                },
                () -> {
                    if (running.compareAndSet(true, false)) { // Only update UI if we were still running naturally
                        actionBtn.setText("▶ Start");
                        actionBtn.setBackground(ACCENT);
                        int t = tested.get();
                        int h = hits.get();
                        progressBar.setValue(total);
                        progressBar.setString("Done — " + t + " tested, " + h + " hits");
                        statusLabel.setText("Finished");

                    }
                });
    }

    private void stopFuzz() {
        running.set(false);
        if (activeExecutor != null && !activeExecutor.isShutdown()) {
            activeExecutor.shutdownNow();
        }
        activeExecutor = null;
        actionBtn.setText("▶ Start");
        actionBtn.setBackground(ACCENT);
        statusLabel.setText("Stopped");
    }

    private void clearResults() {
        results.clear();
        tableModel.setRowCount(0);
        if (requestEditor != null)
            requestEditor.setMessage(new byte[0], true);
        if (responseEditor != null)
            responseEditor.setMessage(new byte[0], false);
        progressBar.setValue(0);
        progressBar.setString("Ready");
        statusLabel.setText("Idle");
        tested.set(0);
        hits.set(0);
    }

    private void addResult(FuzzResult r) {
        results.add(r);
        int idx = results.size() - 1;
        Object statusObj = r.statusCode != null ? r.statusCode : -1;
        tableModel.addRow(new Object[] {
                idx, statusObj, r.bodyLength, r.rawPath, r.label, r.note
        });
        // Throttle auto-scroll: only scroll if the user is already at the bottom
        JScrollPane scrollPane = (JScrollPane) resultsTable.getParent().getParent();
        JScrollBar verticalBar = scrollPane.getVerticalScrollBar();
        boolean isAtBottom = (verticalBar.getValue() + verticalBar.getVisibleAmount() >= verticalBar.getMaximum() - 30);

        if (isAtBottom) {
            int lastViewIdx = resultsTable.getRowCount() - 1;
            if (lastViewIdx >= 0) {
                resultsTable.scrollRectToVisible(resultsTable.getCellRect(lastViewIdx, 0, true));
            }
        }
    }

    private void onRowSelected() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) {
            if (responseEditor != null)
                responseEditor.setMessage(new byte[0], false);
            return;
        }
        int row = resultsTable.convertRowIndexToModel(viewRow);
        if (row < 0 || row >= results.size())
            return;

        FuzzResult r = results.get(row);

        if (r.reqResp != null && r.reqResp.request() != null) {
            if (requestEditor != null)
                requestEditor.setMessage(r.reqResp.request().toByteArray().getBytes(), true);
        } else {
            if (requestEditor != null)
                requestEditor.setMessage(new byte[0], true);
        }

        if (r.reqResp != null && r.reqResp.response() != null) {
            if (responseEditor != null)
                responseEditor.setMessage(r.reqResp.response().toByteArray().getBytes(), false);
        } else {
            if (responseEditor != null)
                responseEditor.setMessage(new byte[0], false);
        }
    }

    private FuzzConfig buildConfig() {
        FuzzConfig cfg = new FuzzConfig();
        cfg.injectMode = (String) injectModeBox.getSelectedItem();
        cfg.fuzzTarget = (String) fuzzTargetBox.getSelectedItem();
        cfg.permuteHeaders = permuteHeadersBox.isSelected();
        cfg.threads = (Integer) threadsSpinner.getValue();
        cfg.onlyHits = onlyHitsBox.isSelected();
        cfg.hideErrors = hideErrorsBox.isSelected();
        cfg.useProgrammatic = programmaticBox.isSelected();
        cfg.filterCodes = filterCodesField.getText().trim();

        // Extract payloads
        for (int i = 0; i < payloadsTableModel.getRowCount(); i++) {
            Boolean isSelected = (Boolean) payloadsTableModel.getValueAt(i, 0);
            if (isSelected != null && isSelected) {
                String payload = (String) payloadsTableModel.getValueAt(i, 1);
                if (payload != null && !payload.isEmpty()) {
                    cfg.customWordlist.add(payload);
                }
            }
        }

        for (int i = 0; i < headersTableModel.getRowCount(); i++) {
            Boolean isSelected = (Boolean) headersTableModel.getValueAt(i, 0);
            if (isSelected != null && isSelected) {
                String key = (String) headersTableModel.getValueAt(i, 1);
                String val = (String) headersTableModel.getValueAt(i, 2);
                if (key != null && !key.trim().isEmpty() && val != null && !val.trim().isEmpty()) {
                    cfg.extraHeaders.put(key.trim(), val.trim());
                }
            }
        }

        return cfg;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers / Styling
    // ────────────────────────────────────────────────────────────────────────

    private <T extends JLabel> T styled(T c, Color fg) {
        c.setForeground(fg);
        return c;
    }

    private void styleCombo(JComboBox<String> cb) {
        cb.setBackground(BG_MID);
        cb.setForeground(FG);
        cb.setMaximumSize(new Dimension(120, 28));
    }

    private void styleSpinner(JSpinner sp) {
        sp.setBackground(BG_MID);
        sp.setMaximumSize(new Dimension(70, 28));
        ((JSpinner.DefaultEditor) sp.getEditor()).getTextField().setBackground(BG_MID);
        ((JSpinner.DefaultEditor) sp.getEditor()).getTextField().setForeground(FG);
    }

    private JCheckBox styleCheck(JCheckBox cb) {
        cb.setBackground(BG_LIGHT);
        cb.setForeground(FG);
        return cb;
    }

    private void styleTextField(JTextField tf) {
        tf.setBackground(BG_MID);
        tf.setForeground(FG);
        tf.setCaretColor(FG);
        tf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BG_LIGHT),
                BorderFactory.createEmptyBorder(2, 4, 2, 4)));
    }

    private JButton makeButton(String text, Color bg, Color fg) {
        JButton btn = new JButton(text);
        btn.setBackground(bg);
        btn.setForeground(fg);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }

    // ────────────────────────────────────────────────────────────────────────
    // Color-coded cell renderer
    // ────────────────────────────────────────────────────────────────────────

    private class StatusCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setBackground(isSelected ? ACCENT : BG_MID);
            setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

            int modelRow = table.convertRowIndexToModel(row);

            if (!isSelected && modelRow < results.size()) {
                FuzzResult r = results.get(modelRow);
                Color rowFg;
                if (r.statusCode == null) {
                    rowFg = GRAY;
                    setText("ERR");
                } else if (r.statusCode == 200 || r.statusCode == 201 || r.statusCode == 206) {
                    rowFg = GREEN;
                } else if (r.statusCode == 301 || r.statusCode == 302
                        || r.statusCode == 307 || r.statusCode == 308) {
                    rowFg = CYAN;
                } else if (r.statusCode == 403) {
                    rowFg = RED;
                } else if (r.statusCode == 404) {
                    rowFg = ORANGE;
                } else {
                    rowFg = YELLOW;
                }
                setForeground(rowFg);
            } else {
                setForeground(isSelected ? Color.WHITE : FG);
            }
            return this;
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // IMessageEditorController implementation for Render tab
    // ────────────────────────────────────────────────────────────────────────

    @Override
    public IHttpService getHttpService() {
        if (currentTarget == null || currentTarget.request() == null)
            return null;
        burp.api.montoya.http.HttpService ts = currentTarget.request().httpService();
        return new IHttpService() {
            @Override
            public String getHost() {
                return ts.host();
            }

            @Override
            public int getPort() {
                return ts.port();
            }

            @Override
            public String getProtocol() {
                return ts.secure() ? "https" : "http";
            }
        };
    }

    @Override
    public byte[] getRequest() {
        if (requestEditor == null)
            return new byte[0];
        return requestEditor.getMessage();
    }

    @Override
    public byte[] getResponse() {
        if (responseEditor == null)
            return new byte[0];
        return responseEditor.getMessage();
    }
}
