package main

import (
	"regexp"

	"context"

	"github.com/davedean/go-socks5/pkg/socks5"
)

// PermitDestAddrPattern returns a RuleSet which selectively allows addresses
func PermitDestAddrPattern(pattern string) socks5.RuleSet {
	return &PermitDestAddrPatternRuleSet{pattern}
}

// PermitDestAddrPatternRuleSet is an implementation of the RuleSet which
// enables filtering supported destination address
type PermitDestAddrPatternRuleSet struct {
	AllowedFqdnPattern string
}

func (p *PermitDestAddrPatternRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	match, _ := regexp.MatchString(p.AllowedFqdnPattern, req.DestAddr.FQDN)
	return ctx, match
}
