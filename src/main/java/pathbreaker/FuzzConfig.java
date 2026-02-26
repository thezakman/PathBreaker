package pathbreaker;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class FuzzConfig {
    public String injectMode = "tail";
    public String fuzzTarget = "Both";
    public int threads = 10;
    public boolean permuteHeaders = true;
    public boolean onlyHits = false;
    public boolean hideErrors = false;
    public String filterCodes = "";
    public boolean useProgrammatic = true;
    public List<String> customWordlist = new ArrayList<>();
    public Map<String, String> extraHeaders = new LinkedHashMap<>();

    public Set<Integer> parsedFilterCodes() {
        if (filterCodes == null || filterCodes.isBlank())
            return Set.of();
        return Arrays.stream(filterCodes.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> {
                    try {
                        return Integer.parseInt(s);
                    } catch (NumberFormatException e) {
                        return -1;
                    }
                })
                .filter(i -> i > 0)
                .collect(Collectors.toSet());
    }
}
