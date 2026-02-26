package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import javax.swing.*;

/**
 * Main tabbed panel for PathBreaker – hosts the Path Fuzzer and Header Fuzzer tabs.
 */
public class PathBreakerTab extends JTabbedPane {

    private final PathFuzzerPanel   pathFuzzerPanel;
    private final HeaderFuzzerPanel headerFuzzerPanel;

    public PathBreakerTab(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        pathFuzzerPanel   = new PathFuzzerPanel(callbacks, helpers);
        headerFuzzerPanel = new HeaderFuzzerPanel(callbacks, helpers);

        addTab("Path Fuzzer",   pathFuzzerPanel);
        addTab("Header Fuzzer", headerFuzzerPanel);
    }

    /** Populate the Path Fuzzer tab from a request selected in another Burp tool. */
    public void sendToPathFuzzer(IHttpRequestResponse message) {
        pathFuzzerPanel.loadRequest(message);
        setSelectedIndex(0);
    }

    /** Populate the Header Fuzzer tab from a request selected in another Burp tool. */
    public void sendToHeaderFuzzer(IHttpRequestResponse message) {
        headerFuzzerPanel.loadRequest(message);
        setSelectedIndex(1);
    }
}
