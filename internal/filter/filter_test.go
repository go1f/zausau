package filter

import (
	"testing"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func TestShouldSkipPlaceholders(t *testing.T) {
	f, err := New(model.FilterSet{
		PlaceholderValues: []string{"changeme"},
		PlaceholderPatterns: []string{
			`(?i)^your_.+`,
		},
		MaskedPatterns: []string{
			`^[*xX#-]{6,}$`,
		},
		HashPatterns: []string{
			`(?i)^[a-f0-9]{32}$`,
		},
		UUIDPatterns: []string{
			`(?i)^[a-f0-9]{8}-`,
		},
		VariablePatterns: []string{
			`^\$\{[A-Z0-9_]+\}$`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{"changeme", "your_token_here", "********", "5f4dcc3b5aa765d61d8327deb882cf99", "${TOKEN}", "${PGPASSWORD:-$(<", "process.env.API_KEY"}
	for _, value := range cases {
		if skip, _ := f.ShouldSkip(value); !skip {
			t.Fatalf("expected %q to be skipped", value)
		}
	}
}
