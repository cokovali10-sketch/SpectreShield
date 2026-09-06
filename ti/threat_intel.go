//go:build linux

package ti

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type IOC struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Confidence float64    `json:"confidence"`
	Source     string     `json:"source"`
	Tags       []string   `json:"tags"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Expiry     *time.Time `json:"expiry,omitempty"`
}

type Feed struct {
	Name     string     `json:"name"`
	URL      string     `json:"url"`
	Format   string     `json:"format"`
	Enabled  bool       `json:"enabled"`
	LastSync *time.Time `json:"last_sync,omitempty"`
}

type Database struct {
	iocs  map[string]*IOC
	feeds []*Feed
	mu    sync.RWMutex
}

func NewDatabase() *Database {
	return &Database{
		iocs: make(map[string]*IOC),
	}
}

func (db *Database) AddIOC(ioc *IOC) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.iocs[ioc.Value] = ioc
}

func (db *Database) CheckIP(ip string) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.iocs[ip]
}

func (db *Database) CheckDomain(domain string) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.iocs[domain]
}

func (db *Database) CheckHash(hash string) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.iocs[hash]
}

func (db *Database) CheckURL(url string) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.iocs[url]
}

func (db *Database) Check(data string) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if ioc, ok := db.iocs[data]; ok {
		return ioc
	}
	return nil
}

func (db *Database) GetStats() map[string]int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	stats := map[string]int{"total": len(db.iocs)}
	for _, ioc := range db.iocs {
		stats[ioc.Type]++
	}
	return stats
}

func (db *Database) ExportJSON(path string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	data, err := json.MarshalIndent(db.iocs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (db *Database) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var iocs map[string]*IOC
	if err := json.Unmarshal(data, &iocs); err != nil {
		return err
	}
	db.mu.Lock()
	db.iocs = iocs
	db.mu.Unlock()
	return nil
}

func (db *Database) LoadDefaults() {
	defaults := []*IOC{
		{ID: "1", Type: "ip", Value: "1.2.3.4", Confidence: 0.9, Source: "known_c2", Tags: []string{"c2"}},
		{ID: "2", Type: "ip", Value: "5.6.7.8", Confidence: 0.85, Source: "known_c2", Tags: []string{"c2"}},
		{ID: "3", Type: "hash", Value: "d41d8cd98f00b204e9800998ecf8427e", Confidence: 0.95, Source: "malware_hash", Tags: []string{"malware"}},
		{ID: "4", Type: "domain", Value: "evil.com", Confidence: 0.9, Source: "threat_intel", Tags: []string{"c2", "phishing"}},
	}
	for _, ioc := range defaults {
		db.AddIOC(ioc)
	}
}

func HashMD5(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])
}

func HashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func ValidateDomain(domain string) bool {
	return strings.Contains(domain, ".")
}

func NormalizeIOC(value, iocType string) string {
	switch iocType {
	case "ip":
		ip := net.ParseIP(value)
		if ip != nil {
			return ip.String()
		}
	case "domain":
		return strings.ToLower(strings.TrimSpace(value))
	case "hash":
		return strings.ToLower(strings.TrimSpace(value))
	case "url":
		return strings.ToLower(strings.TrimSpace(value))
	}
	return value
}

func ClassifyIOC(value string) string {
	if net.ParseIP(value) != nil {
		return "ip"
	}
	if strings.Contains(value, "://") {
		return "url"
	}
	if strings.Contains(value, "@") {
		return "email"
	}
	if strings.Contains(value, ".") {
		return "domain"
	}
	if len(value) == 32 || len(value) == 64 {
		return "hash"
	}
	return "unknown"
}

func (db *Database) SearchIOC(query string) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	query = strings.ToLower(query)
	var results []*IOC
	for _, ioc := range db.iocs {
		if strings.Contains(strings.ToLower(ioc.Value), query) ||
			strings.Contains(strings.ToLower(ioc.Source), query) ||
			strings.Contains(strings.ToLower(ioc.Type), query) {
			results = append(results, ioc)
		}
	}
	return results
}

func (db *Database) RemoveIOC(value string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.iocs[value]; exists {
		delete(db.iocs, value)
		return true
	}
	return false
}

func (db *Database) AddFeed(feed *Feed) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.feeds = append(db.feeds, feed)
}

func (db *Database) GetFeeds() []*Feed {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*Feed, len(db.feeds))
	copy(result, db.feeds)
	return result
}

func (db *Database) CleanupExpired() int {
	db.mu.Lock()
	defer db.mu.Unlock()
	now := time.Now()
	removed := 0
	for key, ioc := range db.iocs {
		if ioc.Expiry != nil && ioc.Expiry.Before(now) {
			delete(db.iocs, key)
			removed++
		}
	}
	return removed
}

// EnrichIOC enriches an IOC with additional context
func (db *Database) EnrichIOC(ioc *IOC) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if existing, ok := db.iocs[ioc.Value]; ok {
		ioc.FirstSeen = existing.FirstSeen
		if ioc.Source != "" {
			ioc.Source = existing.Source + "," + ioc.Source
		}
	}
	return ioc
}

// CorrelateIOCs finds related IOCs
func (db *Database) CorrelateIOCs(ioc *IOC) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var related []*IOC
	for _, existing := range db.iocs {
		if existing.Value == ioc.Value {
			continue
		}
		if db.tagsOverlap(existing.Tags, ioc.Tags) || existing.Source == ioc.Source {
			related = append(related, existing)
		}
	}
	return related
}

func (db *Database) tagsOverlap(a, b []string) bool {
	set := make(map[string]bool)
	for _, tag := range a {
		set[tag] = true
	}
	for _, tag := range b {
		if set[tag] {
			return true
		}
	}
	return false
}

// GetIOCStats returns detailed IOC statistics
func (db *Database) GetIOCStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	stats := map[string]interface{}{
		"total":     len(db.iocs),
		"by_type":   map[string]int{},
		"by_source": map[string]int{},
		"by_tag":    map[string]int{},
	}

	byType := stats["by_type"].(map[string]int)
	bySource := stats["by_source"].(map[string]int)
	byTag := stats["by_tag"].(map[string]int)

	for _, ioc := range db.iocs {
		byType[ioc.Type]++
		bySource[ioc.Source]++
		for _, tag := range ioc.Tags {
			byTag[tag]++
		}
	}

	return stats
}

// ExportAll exports all IOCs to a file
func (db *Database) ExportAll(path string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()
	data, err := json.MarshalIndent(db.iocs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// GetIOCByType returns IOCs of a specific type
func (db *Database) GetIOCByType(iocType string) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*IOC
	for _, ioc := range db.iocs {
		if ioc.Type == iocType {
			result = append(result, ioc)
		}
	}
	return result
}

// GetIOCByTag returns IOCs with a specific tag
func (db *Database) GetIOCByTag(tag string) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*IOC
	for _, ioc := range db.iocs {
		for _, t := range ioc.Tags {
			if t == tag {
				result = append(result, ioc)
				break
			}
		}
	}
	return result
}

// GetIOCBySource returns IOCs from a specific source
func (db *Database) GetIOCBySource(source string) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var result []*IOC
	for _, ioc := range db.iocs {
		if ioc.Source == source {
			result = append(result, ioc)
		}
	}
	return result
}

// UpdateIOC updates an existing IOC
func (db *Database) UpdateIOC(ioc *IOC) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.iocs[ioc.Value]; exists {
		db.iocs[ioc.Value] = ioc
		return true
	}
	return false
}

// GetTopIOCs returns the top IOCs by confidence
func (db *Database) GetTopIOCs(limit int) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()

	type iocWithConf struct {
		ioc  *IOC
		conf float64
	}
	var sorted []iocWithConf
	for _, ioc := range db.iocs {
		sorted = append(sorted, iocWithConf{ioc, ioc.Confidence})
	}
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].conf > sorted[i].conf {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var result []*IOC
	for i := 0; i < limit && i < len(sorted); i++ {
		result = append(result, sorted[i].ioc)
	}
	return result
}

// GetRecentIOCs returns IOCs seen in the last N hours
func (db *Database) GetRecentIOCs(hours int) []*IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	var result []*IOC
	for _, ioc := range db.iocs {
		if ioc.LastSeen.After(cutoff) {
			result = append(result, ioc)
		}
	}
	return result
}

// GenerateReport generates a threat intelligence report
func (db *Database) GenerateReport() string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	report := "# Threat Intelligence Report\n\n"
	report += fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339))
	report += fmt.Sprintf("Total IOCs: %d\n\n", len(db.iocs))

	stats := db.GetIOCStats()
	byType := stats["by_type"].(map[string]int)
	report += "## By Type\n"
	for t, count := range byType {
		report += fmt.Sprintf("- %s: %d\n", t, count)
	}

	byTag := stats["by_tag"].(map[string]int)
	report += "\n## By Tag\n"
	for tag, count := range byTag {
		report += fmt.Sprintf("- %s: %d\n", tag, count)
	}

	return report
}

// MatchForIOC checks if data matches any known IOC
func (db *Database) MatchForIOC(data string) *IOC {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if ioc, ok := db.iocs[data]; ok {
		return ioc
	}
	// Check substring matches for domains/URLs
	for _, ioc := range db.iocs {
		if strings.Contains(data, ioc.Value) {
			return ioc
		}
	}
	return nil
}

// BulkAdd adds multiple IOCs at once
func (db *Database) BulkAdd(iocs []*IOC) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	added := 0
	for _, ioc := range iocs {
		db.iocs[ioc.Value] = ioc
		added++
	}
	return added
}

// GetFeedsList returns all configured feeds
func (db *Database) GetFeedsList() []*Feed {
	db.mu.RLock()
	defer db.mu.RUnlock()
	result := make([]*Feed, len(db.feeds))
	copy(result, db.feeds)
	return result
}

// RemoveFeed removes a feed by name
func (db *Database) RemoveFeed(name string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	for i, feed := range db.feeds {
		if feed.Name == name {
			db.feeds = append(db.feeds[:i], db.feeds[i+1:]...)
			return true
		}
	}
	return false
}
