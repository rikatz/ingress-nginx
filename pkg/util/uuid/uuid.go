package uuid

import (
	"fmt"

	"github.com/google/uuid"
)

func CheckUUID(value string) error {
	if _, err := uuid.Parse(value); err != nil {
		return fmt.Errorf("field contains invalid UUID: %w", err)
	}
	return nil
}
