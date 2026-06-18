package stack

import (
    "context"
    "errors"
    "fmt"

    "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

type Config struct {
    Plugins    []string `json:"plugins"`
    Metrics    validator.Metrics `json:"-"`
    PluginMap map[string]validator.TokenValidatorAndSelectorGenerator`json:"-"`
}

func (c *Config) ValidateConfig(AllPlugins map[string]validator.TokenValidatorAndSelectorGenerator) error {
    c.PluginMap = make(map[string]validator.TokenValidatorAndSelectorGenerator)
    for _, plugin := range c.Plugins {
        if p, exists := AllPlugins[plugin]; exists {
		c.PluginMap[plugin] = p
	} else {
            return fmt.Errorf("plugin %s not found", plugin)
        }
    }
    if len(c.Plugins) == 0 {
        return errors.New("you must have at least one plugin defined")
    }
    return nil
}

func (c *Config) NewValidator() (validator.TokenValidatorAndSelectorGenerator, error) {
    return NewValidator(*c)
}

type Validator struct {
    config       Config
}

func NewValidator(cfg Config) (*Validator, error) {
    return &Validator{
        config:       cfg,
    }, nil
}

func (v *Validator) Validate(ctx context.Context, token string, purpose validator.Purpose) (validator.Claims, error) {
    allClaims := make(map[string]validator.Claims)
    singlePluginName := ""
    l := len(allClaims)
    if l == 1 {
        singlePluginName = v.config.Plugins[0]
    }
    tokens, err := parsePluginTokens(token, singlePluginName)
    if err != nil {
        return nil, err
    }
    for pluginName, pluginToken := range tokens {
        if plugin, exists := v.config.PluginMap[pluginName]; exists {
          claims, err := plugin.Validate(ctx, pluginToken, purpose)
	  if err != nil {
		return nil, err
	  }
	  allClaims[pluginName] = claims
	} else {
          return nil, fmt.Errorf("plugin %s not found", pluginName)
	}
    }
	if len(allClaims) != len(v.config.Plugins) {
		return nil, fmt.Errorf("missing tokens: expected %d plugin tokens, got %d", len(v.config.Plugins), len(allClaims))
	}

    return &Claims {
	    PluginClaims: allClaims,
    }, nil
}

