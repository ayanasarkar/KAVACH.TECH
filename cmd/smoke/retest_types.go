package main

// retestItem is one issue in a retest's delta, as the console API returns it.
type retestItem struct {
	Key       string `json:"key"`
	FindingID string `json:"finding_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Asset     string `json:"asset"`
	Change    string `json:"change"`
}

// retestRec is one retest as the console API returns it.
type retestRec struct {
	ID        string       `json:"id"`
	FindingID string       `json:"finding_id"`
	OldStep   string       `json:"old_step"`
	NewStep   string       `json:"new_step"`
	Analyst   string       `json:"analyst"`
	Status    string       `json:"status"`
	Delta     []retestItem `json:"delta"`
}
