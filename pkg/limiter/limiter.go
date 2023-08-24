package limiter

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	rl "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang/protobuf/ptypes/duration"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type metrics struct {
	okResp      prometheus.Counter
	limitedResp prometheus.Counter
	unkownResp  prometheus.Counter
}

func newMetrics(r prometheus.Registerer) *metrics {
	var m metrics

	m.okResp = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_ok_responses",
		Help: "Total ok responses",
	})

	m.limitedResp = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_limited_requests",
		Help: "Total limited responses",
	})

	m.unkownResp = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_unknown_requests",
		Help: "Total unknown responses",
	})

	r.MustRegister(m.okResp, m.limitedResp, m.unkownResp)
	return &m
}

type LimiterService struct {
	rulesService   RulesService
	counterService CounterService
	logger         *logrus.Logger
	metrics        *metrics
}

func NewLimiterService(
	rulesService RulesService,
	counterService CounterService,
	logger *logrus.Logger,
	registerer prometheus.Registerer) *LimiterService {

	metrics := newMetrics(registerer)

	return &LimiterService{
		rulesService:   rulesService,
		counterService: counterService,
		logger:         logger,
		metrics:        metrics,
	}
}

func (l *LimiterService) ShouldRateLimit(ctx context.Context, req *pb.RateLimitRequest) (response *pb.RateLimitResponse, err error) {
	// data, _ := json.Marshal(req)
	// fmt.Println(string(data))
	defer func() {
		// data, _ = json.Marshal(response)
		// fmt.Println(string(data))
		if err != nil {
			return
		}

		switch response.OverallCode {
		case pb.RateLimitResponse_OVER_LIMIT:
			l.metrics.limitedResp.Inc()
		case pb.RateLimitResponse_OK:
			l.metrics.okResp.Inc()
		case pb.RateLimitResponse_UNKNOWN:
			l.metrics.unkownResp.Inc()
		}
	}()

	response = &pb.RateLimitResponse{
		OverallCode: pb.RateLimitResponse_UNKNOWN,
	}
	// service does not allow 0 hits addend
	if req.HitsAddend == 0 {
		req.HitsAddend = 1
	}

	rules := []*Rule{}
	keys := []string{}
	isOverLimit := false
	statuses := []*pb.RateLimitResponse_DescriptorStatus{}
	now := time.Now().Unix()
	for _, desc := range req.Descriptors {
		rule, err := l.rulesService.GetRatelimitRule(req.Domain, desc)
		if err != nil {
			if err == ErrNoMatchedRule {
				continue
			}
		}
		rules = append(rules, rule)
		windowSize := timeUnitToWindowSize(rule.Limit.Unit)
		key := generateKey(req.Domain, desc, rule, now/windowSize)
		keys = append(keys, key)
		status := &pb.RateLimitResponse_DescriptorStatus{
			CurrentLimit: &pb.RateLimitResponse_RateLimit{
				RequestsPerUnit: rule.Limit.Requests,
				Unit:            timeUnitToPb(rule.Limit.Unit),
			},
			DurationUntilReset: &duration.Duration{
				Seconds: windowSize - (now % windowSize),
			},
			Code:           pb.RateLimitResponse_UNKNOWN,
			LimitRemaining: rule.Limit.Requests,
		}
		currUsage, err := l.counterService.Get(ctx, key)
		if err != nil {
			if rule.SyncRate == 0 {
				currUsage, err = l.counterService.GetFromStorage(ctx, key)
				if err != nil {
					statuses = append(statuses, status)
					continue
				}
			}
		}
		if currUsage > rule.Limit.Requests {
			status.Code = pb.RateLimitResponse_OVER_LIMIT
			status.LimitRemaining = 0
			isOverLimit = true
			if rule.SyncRate == 0 {
				l.counterService.Increment(ctx, key, currUsage, now+(timeUnitToWindowSize(rule.Limit.Unit)*2), -1)
			}
		} else {
			status.LimitRemaining = rule.Limit.Requests - currUsage
		}
		statuses = append(statuses, status)
	}
	if isOverLimit {
		response.OverallCode = pb.RateLimitResponse_OVER_LIMIT
		response.Statuses = statuses
		return response, nil
	}
	for i, rule := range rules {
		var currUsage uint32
		//check if its already over-limit on local storage
		key := keys[i]

		// current usage must be available 2 buckets later for interpolation
		ttl := now + (timeUnitToWindowSize(rule.Limit.Unit) * 2)
		if rule.SyncRate == 0 {
			currUsage, err = l.counterService.IncrementOnStorage(ctx, key, req.HitsAddend, ttl)
			if err != nil {
				continue
			}
		} else {
			currUsage, err = l.counterService.Increment(ctx, key, req.HitsAddend, ttl, rule.SyncRate)
			if err != nil {
				continue
			}
		}

		rate := currUsage
		if rate > rule.Limit.Requests {
			response.OverallCode = pb.RateLimitResponse_OVER_LIMIT
			statuses[i].Code = pb.RateLimitResponse_OVER_LIMIT
			statuses[i].LimitRemaining = 0
			// if its already over-limit, we set it to local storage
			if rule.SyncRate == 0 {
				l.counterService.Increment(ctx, key, rate, ttl, -1)
			}
		} else {
			// // if its already over-limit, we shouldnt tag it as ok
			if response.OverallCode == pb.RateLimitResponse_UNKNOWN {
				response.OverallCode = pb.RateLimitResponse_OK
			}
			statuses[i].Code = pb.RateLimitResponse_OK
			statuses[i].LimitRemaining = rule.Limit.Requests - currUsage
		}
	}
	response.Statuses = statuses
	return response, nil
}

func generateKey(domain string, desc *rl.RateLimitDescriptor, rule *Rule, timeValue int64) string {
	usedLimitDescriptorEntries := make(map[string]bool)
	for _, label := range rule.Entries {
		usedLimitDescriptorEntries[label.Key] = true
	}

	descriptorKeyValues := make([]string, 0, len(desc.Entries))
	for _, entry := range desc.Entries {
		if _, exists := usedLimitDescriptorEntries[entry.Key]; exists {
			descriptorKeyValues = append(descriptorKeyValues, entry.Key+"="+entry.Value)
		}
	}
	sort.Strings(descriptorKeyValues)

	return domain + ":" + strings.Join(descriptorKeyValues, "&") + ":" + rule.Limit.Unit + ":" + strconv.FormatInt(timeValue, 10)
}
