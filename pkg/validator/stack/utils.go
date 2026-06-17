package stack

import (
	"errors"
	"fmt"
	"strings"
)

func parsePluginTokens(token string, singlePluginName string) (map[string]string, error) {
	result := make(map[string]string)
	token = strings.TrimSpace(token)

	if token == "" {
		return nil, errors.New("token string is empty")
	}
	if singlePluginName != "" {
		result[singlePluginName] = token
		return  result, nil
	}

	segments := strings.Split(token, ":")

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, errors.New("malformed token: found an empty segment or extra ':'")
		}

		pluginName, token, found := strings.Cut(segment, "=")

		pluginName = strings.TrimSpace(pluginName)
		token = strings.TrimSpace(token)

		if !found {
			return nil, fmt.Errorf("malformed token: segment '%s' is missing an '=' separator", segment)
		}
		if pluginName == "" {
			return nil, fmt.Errorf("malformed token: missing plugin name in segment '%s'", segment)
		}
		if token == "" {
			return nil, fmt.Errorf("malformed token: missing token value for plugin '%s'", pluginName)
		}

		if _, exists := result[pluginName]; exists {
			return nil, fmt.Errorf("malformed token: duplicate plugin '%s' detected", pluginName)
		}

		result[pluginName] = token
	}

	return result, nil
}
