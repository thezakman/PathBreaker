package pathbreaker;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class PathBreakerExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("PathBreaker");

        PathBreakerTab tab = new PathBreakerTab(api);

        api.userInterface().registerSuiteTab("PathBreaker", tab.getComponent());
        api.userInterface().registerContextMenuItemsProvider(
            new PathBreakerContextMenu(api, tab)
        );

        api.logging().logToOutput("PathBreaker loaded — right-click any request → Send to PathBreaker");
    }
}
