package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagementEntryPaginationAndSearch(t *testing.T) {
	t.Parallel()
	catalog := newMemoryCatalog()
	for index := 0; index < 25; index++ {
		catalog.entries["agent-1"] = append(catalog.entries["agent-1"], HTTPEntry{RuleRef: fmt.Sprint(index), FrontendURL: fmt.Sprintf("https://site-%02d.example.com", index), Attached: true, Mode: ModeObserve})
	}
	controller := newUIController(t, uiControllerOptions{catalog: catalog, omitEvents: true})
	for _, test := range []struct {
		query              string
		total, page, count int
		first              string
	}{
		{"page_size=10&entry_page=2", 25, 2, 10, "10"},
		{"page_size=10&entry_page=999", 25, 3, 5, "20"},
		{"page_size=10&entry_query=SITE-02", 1, 1, 1, "2"},
		{"page_size=10&entry_mode=deny", 0, 1, 0, ""},
	} {
		t.Run(test.query, func(t *testing.T) {
			listed := httptest.NewRecorder()
			controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1&include_events=false&"+test.query, ""))
			payload := decodeWAFState(t, listed.Body.Bytes())
			if listed.Code != http.StatusOK || payload.Error != "" || payload.EntriesPage == nil || payload.EntriesPage.Total != test.total || payload.EntriesPage.Page != test.page || len(payload.Entries) != test.count {
				t.Fatalf("response = %+v", payload)
			}
			if test.count > 0 && payload.Entries[0].RuleRef != test.first {
				t.Fatalf("first = %s", payload.Entries[0].RuleRef)
			}
		})
	}
	for _, query := range []string{"page_size=0", "page_size=101", "page_size=10&entry_page=-1", "page_size=10&entry_mode=invalid"} {
		listed := httptest.NewRecorder()
		controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1&"+query, ""))
		if listed.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", query, listed.Code)
		}
	}
}

func TestManagementEventsPageOnlyExistingSourceRecords(t *testing.T) {
	t.Parallel()
	catalog := newMemoryCatalog()
	for index := 0; index < 23; index++ {
		catalog.events = append(catalog.events, SecurityEvent{Site: "app.example.com", RuleID: fmt.Sprint(index), Disposition: ModeDeny, Reason: "rule_matched"})
	}
	controller := newUIController(t, uiControllerOptions{catalog: catalog, events: catalog})
	listed := httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1&page_size=10&event_page=2", ""))
	payload := decodeWAFState(t, listed.Body.Bytes())
	if !payload.EventsAvailable || payload.EventSummary[ModeDeny] != 23 || len(payload.RecentEvents) != 5 || len(payload.Events) != 10 || payload.Events[0].RuleID != "10" {
		t.Fatalf("existing-source projection = %+v", payload)
	}
	controller.events = nil
	listed = httptest.NewRecorder()
	controller.ServeHTTP(listed, uiRequest(http.MethodGet, "/api/state?agent_id=agent-1&page_size=10", ""))
	payload = decodeWAFState(t, listed.Body.Bytes())
	if payload.EventsAvailable || payload.EventSummary != nil || payload.Error == "" {
		t.Fatal("unavailable source must not be projected as a healthy empty history")
	}
}
