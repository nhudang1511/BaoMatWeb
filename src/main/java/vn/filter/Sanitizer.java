package vn.filter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
public class Sanitizer {
    
    private static final Pattern scriptPattern = Pattern.compile("<script[^>]*?>.*?</script>", Pattern.CASE_INSENSITIVE);
    private static final Pattern htmlPattern = Pattern.compile("<[/!]*?[\\w]+(?:[\\s]+[\\w.\\-]+(?:\\s*=\\s*(?:\".*?\"|'.*?'|[^'\">\\s]+))?)*[\\s]*/?>", Pattern.CASE_INSENSITIVE);
    
    public static String sanitize(String input) {
        String output = input;
        Matcher scriptMatcher = scriptPattern.matcher(output);
        output = scriptMatcher.replaceAll("");
        Matcher htmlMatcher = htmlPattern.matcher(output);
        output = htmlMatcher.replaceAll("");
        return output;
    }
    
}
