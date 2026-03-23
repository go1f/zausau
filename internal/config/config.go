package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func Load(path string) (model.Config, error) {
	var cfg model.Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 2 << 20
	}
	if cfg.DefaultMinScore <= 0 {
		cfg.DefaultMinScore = 0.55
	}
	return cfg, nil
}
