package ejson2env

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

	"al.essio.dev/pkg/shellescape"
)

// ExportEnv writes the passed environment values to the passed
// io.Writer.
func ExportEnv(w io.Writer, values map[string]string) {
	export(w, "export ", values)
}

// ExportQuiet writes the passed environment values to the passed
// io.Writer in %s=%s format.
func ExportQuiet(w io.Writer, values map[string]string) {
	export(w, "", values)
}

func TrimLeadingUnderscoreExportWrapper(exportfunc ExportFunction) ExportFunction {
	return func(w io.Writer, values map[string]string) {
		newValues := make(map[string]string, len(values))

		for key, value := range values {
			newValues[strings.TrimLeft(key, "_")] = value
		}

		exportfunc(w, newValues)
	}
}

// GitHubActionsMaskWrapper wraps an export function to output GitHub Actions
// mask commands before exporting. This prevents secret values from appearing
// in GitHub Actions logs. Only masks values for keys that don't start with
// underscore (public values are not masked).
// Additionally, exports all variables to $GITHUB_ENV for use in subsequent steps.
// The trimUnderscore parameter indicates whether to trim leading underscores from
// key names when exporting to GITHUB_ENV (to match the export statement behavior).
func GitHubActionsMaskWrapper(exportfunc ExportFunction, trimUnderscore bool) ExportFunction {
	return func(w io.Writer, values map[string]string) {
		// Get sorted keys for deterministic output
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Output mask commands and GITHUB_ENV exports
		for _, key := range keys {
			value := values[key]

			// Mask non-underscore-prefixed keys (using original key name)
			if !strings.HasPrefix(key, "_") {
				// Output the raw value for masking (before shell escaping)
				rawValue := strings.Map(func(r rune) rune {
					if unicode.IsControl(r) && r != '\n' {
						return -1
					}
					return r
				}, value)
				if _, err := fmt.Fprintf(w, "echo \"::add-mask::%s\"\n", shellescape.Quote(rawValue)); err != nil {
					fmt.Fprintf(os.Stderr, "ejson2env failed to write mask command: %v\n", err)
				}
			}

			// Determine the key name to use for GITHUB_ENV export
			exportKey := key
			if trimUnderscore {
				exportKey = strings.TrimLeft(key, "_")
			}

			// Export to GITHUB_ENV for all keys
			// Filter control characters from value
			filteredValue := strings.Map(func(r rune) rune {
				if unicode.IsControl(r) && r != '\n' {
					return -1
				}
				return r
			}, value)

			if _, err := fmt.Fprintf(w, "echo \"%s=%s\" >> $GITHUB_ENV\n", exportKey, shellescape.Quote(filteredValue)); err != nil {
				fmt.Fprintf(os.Stderr, "ejson2env failed to write GITHUB_ENV export: %v\n", err)
			}
		}

		// Call the wrapped export function
		exportfunc(w, values)
	}
}

func export(w io.Writer, prefix string, values map[string]string) {
	keys := make([]string, 0, len(values))
	for k := range values {
		if !validKey(k) {
			fmt.Fprintf(os.Stderr, "ejson2env blocked invalid key")
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		value := filteredValue(values[k])
		if _, err := fmt.Fprintf(w, "%s%s=%s\n", prefix, k, value); err != nil {
			fmt.Fprintf(os.Stderr, "ejson2env failed to write export: %v\n", err)
		}
	}
}

func validKey(k string) bool {
	for _, r := range k {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func filteredValue(v string) string {
	printable := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return -1
		}
		return r
	}, v)

	if printable != v {
		fmt.Fprintf(os.Stderr, "ejson2env trimmed control characters from value")
	}

	return shellescape.Quote(printable)
}
