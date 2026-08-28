package releaseselector

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const genericPatchStatus = `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server rejected our request due to an error in our request","reason":"Invalid","details":{},"code":422}`

func TestPatchGitRepositoryMapsOnlyClosedCASResponsesToConflict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		statusCode int
		body       string
		conflict   bool
	}{
		{name: "resource-version-conflict", statusCode: http.StatusConflict, body: `{}`, conflict: true},
		{name: "generic-rfc6902-test-failure", statusCode: http.StatusUnprocessableEntity, body: genericPatchStatus, conflict: true},
		{name: "cause-bearing-422", statusCode: http.StatusUnprocessableEntity, body: `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server rejected our request due to an error in our request","reason":"Invalid","details":{"causes":[{"reason":"FieldValueInvalid"}]},"code":422}`},
		{name: "foreign-message-422", statusCode: http.StatusUnprocessableEntity, body: `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"testing value failed","reason":"Invalid","details":{},"code":422}`},
		{name: "missing-details-422", statusCode: http.StatusUnprocessableEntity, body: `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server rejected our request due to an error in our request","reason":"Invalid","code":422}`},
		{name: "unknown-field-422", statusCode: http.StatusUnprocessableEntity, body: `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"the server rejected our request due to an error in our request","reason":"Invalid","details":{},"code":422,"foreign":true}`},
		{name: "server-error", statusCode: http.StatusInternalServerError, body: genericPatchStatus},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodPatch || request.Header.Get("Content-Type") != "application/json-patch+json" || request.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("unexpected patch request: method=%s content-type=%q authorization=%q", request.Method, request.Header.Get("Content-Type"), request.Header.Get("Authorization"))
				}
				return &http.Response{
					Body:       io.NopCloser(strings.NewReader(test.body)),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Request:    request,
					StatusCode: test.statusCode,
				}, nil
			})
			client := &InClusterClient{
				client:         &http.Client{Transport: transport},
				sourceEndpoint: "https://kubernetes.default.svc/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-system/gitrepositories/flux-system",
				token:          "test-token",
			}
			_, err := client.PatchGitRepository(t.Context(), []JSONPatchOperation{{Operation: "test", Path: "/metadata/resourceVersion", Value: "10"}})
			if errors.Is(err, ErrConflict) != test.conflict {
				t.Fatalf("conflict=%t, want %t: %v", errors.Is(err, ErrConflict), test.conflict, err)
			}
			if !test.conflict && err == nil {
				t.Fatal("foreign HTTP response was accepted")
			}
		})
	}
}
