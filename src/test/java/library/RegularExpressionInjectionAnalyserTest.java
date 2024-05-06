package library;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.*;

class RegularExpressionInjectionAnalyserTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                    "aaa",
                    "((((.+)+.+)+.+)+.+)+",
                    "(\\w|\\.)+@(gmail|yahoo|hotmail)\\.(com|co\\.uk)",
                    "^(.*[\\\\\\/])([^\\\\\\/]+)?$",
                    "([a-zA-Z0-9]{4}\\s){3,8}[a-zA-Z0-9]{1,4}",
                    "^(?<label>3[47][0-9]{13})$",
                    "^\\p{Sc}[0-9]",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
    void shouldCorrectlyIdentifyAsNotVulnerable(String pattern) throws ExecutionException {
        // given
        // when
        boolean isVulnerable = RegularExpressionInjectionAnalyser.isVulnerable(pattern);

        // then
        assertFalse(isVulnerable);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "((((.+)+.+)+.+)+.+)+~",
            "^(a+)+$",
            "([a-zA-Z]+)*",
            "(a|aa)+",
            "(a|a?)+",
            "(.*a){12}",
            "(http|https)\\://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\\-\\._\\?\\,\\'/\\\\\\+&amp;%\\$#\\=~])*",
            "(((ht|f)tp(s?):\\/\\/)|(www\\.[^ \\[\\]\\(\\)\\n\\r\\t]+)|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})\\/)([^ \\[\\]\\(\\),;&quot;'&lt;&gt;\\n\\r\\t]+)([^\\. \\[\\]\\(\\),;&quot;'&lt;&gt;\\n\\r\\t])|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})",
            "[^/](([hH][tT][tT][pP][sS]?|[fF][tT][pP])\\:\\/\\/)?([\\w\\.\\-]+(\\:[\\w\\.\\&%\\$\\-]+)*)?((([^\\s\\(\\)\\<\\>\\\\\\\"\\.\\[\\]\\,@;:]+)(\\.[^\\s\\(\\)\\<\\>\\\\\\\"\\.\\[\\]\\,@;:]+)*(\\.[a-zA-Z]{2,4}))|((([01]?\\d{1,2}|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d{1,2}|2[0-4]\\d|25[0-5])))(\\b\\:(6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3}|0)\\b)?((\\/[^\\/][\\w\\.\\,\\?\\'\\\\\\/\\+&%\\$#\\=~_\\-@]*)*[^\\.\\,\\?\\\"\\'\\(\\)\\[\\]!;<>{}\\s\\x7F-\\xFF])?",
            "(http|https)(www.)?[a-zA-Z0-9@:%._\\+~#?&/=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&/=]*)"
    })
    void shouldCorrectlyIdentifyAsVulnerable(String pattern) throws ExecutionException {
        // given
        // when
        boolean isVulnerable = RegularExpressionInjectionAnalyser.isVulnerable(pattern);

        // then
        assertTrue(isVulnerable);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "((",
            "^(a)\\1$",
            "[a-zA-Z0-9._%+-]+@(((?!gmail|yahoo|hotmail)[a-zA-Z0-9-]+\\.[a-zA-Z]{2,})|((?!gmail|yahoo|hotmail)[a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}))",
            "(?:(?:31(\\/|-|\\.)(?:0?[13578]|1[02]))\\1|(?:(?:29|30)(\\/|-|\\.)(?:0?[13-9]|1[0-2])\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$|^(?:29(\\/|-|\\.)0?2\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\\d|2[0-8])(\\/|-|\\.)(?:(?:0?[1-9])|(?:1[0-2]))\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2})"
    })
    void shouldThrowExceptionGivenPatternIsNotValid(String pattern) {
        // given
        // when
        // then
        assertThrows(Exception.class, () -> RegularExpressionInjectionAnalyser.isVulnerable(pattern));
    }
}
