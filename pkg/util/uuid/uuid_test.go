package uuid

import "testing"

func TestCheckUUID(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "valid UUID",
			value:   "78273c01-a582-4b14-893e-fb1fdb689a63",
			wantErr: false,
		},
		{
			name:    "with some invalid string",
			value:   "some.stupid.string",
			wantErr: true,
		},
		{
			name:    "with another invalid string",
			value:   "78273c01-a582-4b14-893e-fb1fdb689a6x",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckUUID(tt.value); (err != nil) != tt.wantErr {
				t.Errorf("CheckUUID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
