package main

import "testing"

// TestListenPort locks the pod's listener contract to the Helm service port and
// ensures malformed environment values fail before the process starts serving.
func TestListenPort(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "default", value: "", want: 8080},
		{name: "explicit", value: "9090", want: 9090},
		{name: "lowest", value: "1", want: 1},
		{name: "highest", value: "65535", want: 65535},
		{name: "not a number", value: "http", wantErr: true},
		{name: "zero", value: "0", wantErr: true},
		{name: "too high", value: "65536", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := listenPort(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("listenPort(%q) error = %v, wantErr %v", test.value, err, test.wantErr)
			}
			if got != test.want {
				t.Errorf("listenPort(%q) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}
