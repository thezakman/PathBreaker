package pathbreaker;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

public class PathBreakerExtension implements BurpExtension, IBurpExtender {

    public static IBurpExtenderCallbacks legacyCallbacks;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("PathBreaker");

        PathBreakerTab tab = new PathBreakerTab(api);

        api.userInterface().registerSuiteTab("PathBreaker", tab.getComponent());
        api.userInterface().registerContextMenuItemsProvider(
                new PathBreakerContextMenu(api, tab));

        api.logging().logToOutput("PathBreaker loaded — right-click any request → Send to PathBreaker");
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        legacyCallbacks = callbacks;
        // The Montoya API initialize() method handles registering the UI tab and name.
        // We only implement this interface to capture the legacy callbacks object,
        // which allows us to create an IMessageEditor that correctly supports the
        // Render tab.
    }
}
