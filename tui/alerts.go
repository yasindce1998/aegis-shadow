package main

import "time"

type Alert struct {
	Timestamp       uint64   `json:"timestamp"`
	AlertType       string   `json:"alert_type"`
	Severity        string   `json:"severity"`
	PID             uint32   `json:"pid"`
	Context         uint64   `json:"context"`
	Details         string   `json:"details"`
	AnomalyScore    float64  `json:"anomaly_score"`
	CorrelatedTypes []string `json:"correlated_types"`
	IsAttackChain   bool     `json:"is_attack_chain"`
	ReceivedAt      time.Time
}

type AlertRing struct {
	items []Alert
	cap   int
}

func NewAlertRing(capacity int) *AlertRing {
	return &AlertRing{
		items: make([]Alert, 0, capacity),
		cap:   capacity,
	}
}

func (r *AlertRing) Push(a Alert) {
	if len(r.items) >= r.cap {
		r.items = r.items[1:]
	}
	r.items = append(r.items, a)
}

func (r *AlertRing) Items() []Alert {
	return r.items
}

func (r *AlertRing) Len() int {
	return len(r.items)
}
