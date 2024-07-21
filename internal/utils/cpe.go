package utils

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/package-url/packageurl-go"
)

func IsDistroPurl(purl string) (bool, error) {
	// check if the distro query parameter is defined
	parsedPurl, err := url.Parse(purl)
	if err != nil {

		return false, err
	}

	// Parse the query parameters
	queryParams, err := url.ParseQuery(parsedPurl.RawQuery)
	if err != nil {
		return false, fmt.Errorf("failed to parse query parameters: %w", err)
	}

	// Extract the distro parameter
	distro := queryParams.Get("distro")
	if distro == "" {
		return false, nil
	}

	return true, nil
}

func removeDigitSuffix(s string) string {
	reg := regexp.MustCompile(`\.\d+$`)
	s = reg.ReplaceAllString(s, "")
	reg = regexp.MustCompile(`\d+$`)
	return reg.ReplaceAllString(s, "")
}

func normalizePackageName(packageName string) string {
	// remove the version from the package name
	// like python3.11
	// we only want python
	return removeDigitSuffix(packageName)
}

// PurlToCPE maps a package URL (purl) to a Common Platform Enumeration (CPE)
func PurlToCPE(purl string) (string, error) {
	// Parse the purl
	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		return "", fmt.Errorf("failed to parse purl: %w", err)
	}

	// Extract components
	// namespace := parsedPurl.Namespace
	name := normalizePackageName(parsedPurl.Name)
	version := parsedPurl.Version

	// Construct the CPE string
	// This is a simplified mapping; adjust based on your specific requirements
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		url.PathEscape(name), url.PathEscape(name), url.PathEscape(version))

	return cpe, nil
}
