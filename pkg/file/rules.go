package file

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	rl "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	"github.com/fsnotify/fsnotify"
	"github.com/pkg/errors"
	"github.com/samueltorres/r8limiter/pkg/limiter"
	"github.com/spf13/viper"
)

type RulesService struct {
	mux         *sync.RWMutex
	viper       *viper.Viper
	rulesConfig *limiter.RulesConfig
	rulesIndex  map[string]*limiter.Rule
	ruleCount   int
}

func NewRuleService(file string) (*RulesService, error) {
	if file == "" {
		return nil, errors.Errorf("rules file must be provided")
	}

	v := viper.New()
	v.SetConfigFile(file)
	v.SetConfigType("yaml")

	err := v.ReadInConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error reading in rule file config")
	}

	fc := &RulesService{
		viper: v,
		mux:   &sync.RWMutex{},
	}

	err = fc.loadRules()
	if err != nil {
		return nil, errors.Wrap(err, "error loading rules")
	}

	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
		err := fc.loadRules()
		if err != nil {
			fmt.Println(err)
		}
	})

	return fc, nil
}
func generateKeyRule(ruleKeys *[]string, keyPre string, n int, rateLimitDescriptor *rl.RateLimitDescriptor) {
	if n == len(rateLimitDescriptor.Entries)-1 {
		*ruleKeys = append(*ruleKeys, keyPre+rateLimitDescriptor.Entries[n].Key)
		*ruleKeys = append(*ruleKeys, keyPre+rateLimitDescriptor.Entries[n].Key+"="+rateLimitDescriptor.Entries[n].Value)
		return
	}
	generateKeyRule(ruleKeys, keyPre+rateLimitDescriptor.Entries[n].Key+"&", n+1, rateLimitDescriptor)
	generateKeyRule(ruleKeys, keyPre+rateLimitDescriptor.Entries[n].Key+"="+rateLimitDescriptor.Entries[n].Value+"&", n+1, rateLimitDescriptor)
}
func (rs *RulesService) GetRatelimitRule(domain string, rateLimitDescriptor *rl.RateLimitDescriptor) (*limiter.Rule, error) {
	rs.mux.RLock()
	defer rs.mux.RUnlock()
	ruleKeys := []string{}
	generateKeyRule(&ruleKeys, domain+"?", 0, rateLimitDescriptor)
	// fmt.Println(ruleKeys)
	// fmt.Println(rs.rulesIndex)
	// todo: #performance rankedMatches is escaping to the heap, please review later
	rankedMatches := make([]*limiter.Rule, 0)
	for _, key := range ruleKeys {
		if rule, ok := rs.rulesIndex[key]; ok {
			// fmt.Println(*rule)
			rankedMatches = append(rankedMatches, rule)
		}
	}
	// fmt.Println(rankedMatches)
	if len(rankedMatches) == 0 {
		return nil, limiter.ErrNoMatchedRule
	}
	// 2.1 sort matches by count descending
	sort.Slice(rankedMatches, func(i, j int) bool {
		// return rankedMatches[i].count > rankedMatches[j].count
		return (rankedMatches[i].InnerRank > rankedMatches[j].InnerRank)
	})
	return rankedMatches[0], nil
}

// func (rs *RulesService) GetRatelimitRule(domain string, rateLimitDescriptor *rl.RateLimitDescriptor) (*limiter.Rule, error) {
// 	rs.mux.RLock()
// 	defer rs.mux.RUnlock()

// 	ruleMatchCount := make(map[*limiter.Rule]int, rs.ruleCount)

// 	// 1. find possible matches
// 	for _, entry := range rateLimitDescriptor.Entries {
// 		// 1.1 descriptors that contain a key
// 		key := domain + "." + entry.Key
// 		if descriptors, ok := rs.rulesIndex[key]; ok {
// 			for _, desc := range descriptors {
// 				ruleMatchCount[desc]++
// 			}
// 		}

// 		// 1.2 descriptors that contain a key & value
// 		key = domain + "." + entry.Key + "." + entry.Value
// 		if descriptors, ok := rs.rulesIndex[key]; ok {
// 			for _, desc := range descriptors {
// 				ruleMatchCount[desc]++
// 			}
// 		}
// 	}

// 	if len(ruleMatchCount) == 0 {
// 		return nil, limiter.ErrNoMatchedRule
// 	}
// 	// data, _ := json.Marshal(ruleMatchCount)
// 	fmt.Println(ruleMatchCount)
// 	// 2. filter out matches
// 	type rankedMatch struct {
// 		rule  *limiter.Rule
// 		count int
// 	}

// 	// todo: #performance rankedMatches is escaping to the heap, please review later
// 	rankedMatches := make([]rankedMatch, 0, len(ruleMatchCount))
// 	requestDescriptorLabels := make(map[string]bool)
// 	for _, label := range rateLimitDescriptor.Entries {
// 		requestDescriptorLabels[label.Key] = true
// 		requestDescriptorLabels[label.Key+"."+label.Value] = true
// 	}

// 	for rule, count := range ruleMatchCount {
// 		// todo: add support for regex on rules here
// 		// filter out non existing labels
// 		if len(rateLimitDescriptor.Entries) >= len(rule.Labels) {
// 			descriptorEntriesValid := true
// 			for _, label := range rule.Labels {
// 				// if label value is specified, it must match descriptor's
// 				if label.Value != "" {
// 					if _, exists := requestDescriptorLabels[label.Key+"."+label.Value]; !exists {
// 						descriptorEntriesValid = false
// 						break
// 					}
// 				}
// 				// if there's a label key not present
// 				if _, exists := requestDescriptorLabels[label.Key]; !exists {
// 					descriptorEntriesValid = false
// 					break
// 				}
// 			}

// 			if descriptorEntriesValid {
// 				rankedMatches = append(rankedMatches, rankedMatch{rule, count})
// 			}
// 		}
// 	}

// 	if len(rankedMatches) == 0 {
// 		return nil, limiter.ErrNoMatchedRule
// 	}

// 	// 2.1 sort matches by count descending
// 	sort.Slice(rankedMatches, func(i, j int) bool {
// 		// return rankedMatches[i].count > rankedMatches[j].count
// 		return (rankedMatches[i].count > rankedMatches[j].count) || ((rankedMatches[i].count == rankedMatches[j].count) && (rankedMatches[i].rule.InnerRank > rankedMatches[j].rule.InnerRank))
// 	})

// 	return rankedMatches[0].rule, nil
// 	// // 2.2 return descriptor with matches
// 	// selectedDescriptor := rankedMatches[0]
// 	// maxInnerRank := rankedMatches[0].rule.InnerRank

// 	// // 2.3 check for ties in matches
// 	// for j := 1; j < len(rankedMatches); j++ {
// 	// 	// if there's a tie we need to find the one with the biggest rank
// 	// 	if selectedDescriptor.count == rankedMatches[j].count {
// 	// 		if rankedMatches[j].rule.InnerRank > maxInnerRank {
// 	// 			selectedDescriptor = rankedMatches[j]
// 	// 			maxInnerRank = rankedMatches[j].rule.InnerRank
// 	// 		}
// 	// 	} else {
// 	// 		return selectedDescriptor.rule, nil
// 	// 	}
// 	// }

// 	// return selectedDescriptor.rule, nil
// }

func (rs *RulesService) loadRules() error {
	var rulesConfig limiter.RulesConfig
	err := rs.viper.Unmarshal(&rulesConfig)
	if err != nil {
		return errors.Wrap(err, "error on rule config unmarshal")
	}

	err = validateRules(rulesConfig)
	if err != nil {
		return errors.Wrap(err, "rules file is invalid")
	}

	rs.mux.Lock()

	rs.rulesConfig = &rulesConfig
	rs.rulesIndex, rs.ruleCount = createSearchIndex(&rulesConfig)
	rs.mux.Unlock()
	return nil
}

func createSearchIndex(rc *limiter.RulesConfig) (map[string]*limiter.Rule, int) {
	ruleMap := make(map[string]*limiter.Rule)
	ruleCount := 0
	for _, domain := range rc.Domains {
		for _, rule := range domain.Rules {
			ruleCount++
			key := domain.Domain + "?"
			for i, k := range rule.Entries {
				if k.Value == "" {
					key = key + k.Key
					rule.InnerRank += 10
				} else {
					key = key + k.Key + "=" + k.Value
					rule.InnerRank += 1000
				}
				if i != len(rule.Entries)-1 {
					key = key + "&"
				}
			}
			_, exist := ruleMap[key]
			if exist {
				continue
			}
			ruleMap[key] = rule
		}
	}

	return ruleMap, ruleCount
}

// func createSearchIndex(rc *limiter.RulesConfig) (map[string][]*limiter.Rule, int) {
// 	ruleMap := make(map[string][]*limiter.Rule)
// 	ruleCount := 0
// 	for _, domain := range rc.Domains {
// 		for _, rule := range domain.Rules {
// 			ruleCount++

// 			for _, k := range rule.Labels {
// 				var key string
// 				if k.Value == "" {
// 					key = domain.Domain + "." + k.Key
// 					rule.InnerRank = 10
// 				} else {
// 					key = domain.Domain + "." + k.Key + "." + k.Value
// 					rule.InnerRank = 1000
// 				}

// 				_, exist := ruleMap[key]
// 				if !exist {
// 					ruleMap[key] = []*limiter.Rule{}
// 				}
// 				ruleMap[key] = append(ruleMap[key], rule)
// 			}
// 		}
// 	}

// 	return ruleMap, ruleCount
// }

func validateRules(rulesConfig limiter.RulesConfig) error {

	// validate that there is at least one domain config
	if len(rulesConfig.Domains) == 0 {
		return errors.Errorf("there are no rule domain configs")
	}

	// validate domain rule configs
	domainMap := make(map[string]bool, len(rulesConfig.Domains))

	for i, d := range rulesConfig.Domains {
		// validate domain name
		if d.Domain == "" {
			return errors.Errorf("invalid domain name (%d)", i)
		}

		// validate that there are no duplicated domains
		if _, exists := domainMap[d.Domain]; exists {
			return errors.Errorf("duplicated domain name (%d)", i)
		}
		domainMap[d.Domain] = true

		// validate that the domain has at least one rule
		if len(d.Rules) == 0 {
			return errors.Errorf("domain with no rules (%s)", d.Domain)
		}

		labelsMap := make(map[string]bool)
		for j, r := range d.Rules {

			// validate that there are no rules with the same labels
			labelKeyValues := make([]string, 0, len(r.Entries))
			for _, label := range r.Entries {
				labelKeyValues = append(labelKeyValues, label.Key+"."+label.Value)
			}
			sort.Strings(labelKeyValues)
			labelSummary := strings.Join(labelKeyValues, ":")

			if _, exists := labelsMap[labelSummary]; exists {
				return errors.Errorf("duplicated rule labels - domain (%s) rule (%d)", d.Domain, j)
			}
			labelsMap[labelSummary] = true

			// validate rule limit
			if !validateLimitUnit(r.Limit.Unit) {
				return errors.Errorf("invalid rule limit unit - domain (%s) rule (%d)", d.Domain, j)
			}
			if r.Limit.Requests < 0 {
				return errors.Errorf("invalid rule limit request - domain (%s), rule (%d)", d.Domain, j)
			}
		}
	}

	return nil
}

func validateLimitUnit(unit string) bool {
	switch unit {
	case "second":
		return true
	case "minute":
		return true
	case "hour":
		return true
	case "day":
		return true
	default:
		return false
	}
}
