package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRouterHealthz(t *testing.T) {
	t.Parallel()

	router := NewRouter(Config{}, stubRegistry{}, nil, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}
