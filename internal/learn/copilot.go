package learn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

type Client struct {
	Endpoint   string
	Model      string
	HTTPClient *http.Client
}

func NewClient(endpoint, modelName string) *Client {
	return &Client{
		Endpoint: endpoint,
		Model:    modelName,
		HTTPClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

func (c *Client) Suggest(ctx context.Context, cfg model.Config, report model.ValidationReport, templatePath string) (model.LearnSuggestion, error) {
	var out model.LearnSuggestion
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return out, fmt.Errorf("read prompt template: %w", err)
	}
	prompt := buildPrompt(string(templateData), cfg, report)

	content, err := c.complete(ctx, prompt)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return out, fmt.Errorf("parse suggestion JSON: %w", err)
	}
	return out, nil
}

func (c *Client) complete(ctx context.Context, prompt string) (string, error) {
	systemPrompt := "You are a sensitive data detection rule engineer. Reply with strict JSON only."
	if prefersMessagesAPI(c.Endpoint) {
		return c.callMessages(ctx, systemPrompt, prompt)
	}
	if prefersResponsesAPI(c.Model) {
		content, err := c.callResponses(ctx, systemPrompt, prompt)
		if err == nil {
			return content, nil
		}
		messagesContent, messagesErr := c.callMessages(ctx, systemPrompt, prompt)
		if messagesErr == nil {
			return messagesContent, nil
		}
		if !isRetryableEndpointError(err) {
			return "", fmt.Errorf("model %q prefers /v1/responses or /v1/messages, responses failed (%v) and messages failed (%v)", c.Model, err, messagesErr)
		}
		return "", fmt.Errorf("model %q prefers /v1/responses or /v1/messages, but neither worked. responses error: %v; messages error: %v. Use -model gpt-4.1 or -model gpt-4o for /v1/chat/completions compatibility", c.Model, err, messagesErr)
	}
	return c.callChatCompletions(ctx, systemPrompt, prompt)
}

func (c *Client) callChatCompletions(ctx context.Context, systemPrompt, prompt string) (string, error) {
	payload := map[string]any{
		"model": c.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": systemPrompt,
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.1,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	data, err := c.doJSONRequest(ctx, c.Endpoint, body)
	if err != nil {
		return "", err
	}
	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &completion); err != nil {
		return "", fmt.Errorf("decode chat completion: %w", err)
	}
	if len(completion.Choices) == 0 {
		return "", fmt.Errorf("copilot api returned no chat choices")
	}
	return sanitizeJSONBlock(completion.Choices[0].Message.Content), nil
}

func (c *Client) callResponses(ctx context.Context, systemPrompt, prompt string) (string, error) {
	endpoint, err := companionResponsesEndpoint(c.Endpoint)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"model": c.Model,
		"input": []map[string]any{
			{
				"role": "system",
				"content": []map[string]string{
					{
						"type": "input_text",
						"text": systemPrompt,
					},
				},
			},
			{
				"role": "user",
				"content": []map[string]string{
					{
						"type": "input_text",
						"text": prompt,
					},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	data, err := c.doJSONRequest(ctx, endpoint, body)
	if err != nil {
		return "", err
	}
	var response struct {
		Output []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		OutputText string `json:"output_text"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", fmt.Errorf("decode responses payload: %w", err)
	}
	if strings.TrimSpace(response.OutputText) != "" {
		return sanitizeJSONBlock(response.OutputText), nil
	}
	var parts []string
	for _, item := range response.Output {
		for _, content := range item.Content {
			if strings.TrimSpace(content.Text) != "" {
				parts = append(parts, content.Text)
			}
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("copilot api returned no responses output")
	}
	return sanitizeJSONBlock(strings.Join(parts, "\n")), nil
}

func (c *Client) callMessages(ctx context.Context, systemPrompt, prompt string) (string, error) {
	endpoint, err := companionMessagesEndpoint(c.Endpoint)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"model":      c.Model,
		"max_tokens": 4096,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "dummy")
	req.Header.Set("Anthropic-Version", "2023-06-01")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("call copilot api: %w", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return "", readErr
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("copilot api status %d: %s", resp.StatusCode, string(data))
	}

	var message struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(data, &message); err != nil {
		return "", fmt.Errorf("decode messages payload: %w", err)
	}
	var parts []string
	for _, item := range message.Content {
		if strings.TrimSpace(item.Text) != "" {
			parts = append(parts, item.Text)
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("copilot api returned no messages output")
	}
	return sanitizeJSONBlock(strings.Join(parts, "\n")), nil
}

func (c *Client) doJSONRequest(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call copilot api: %w", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("copilot api status %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func prefersResponsesAPI(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(model, "gpt-5")
}

func companionResponsesEndpoint(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}
	switch {
	case strings.HasSuffix(parsed.Path, "/chat/completions"):
		parsed.Path = strings.TrimSuffix(parsed.Path, "/chat/completions") + "/responses"
	case strings.HasSuffix(parsed.Path, "/responses"):
	default:
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/responses"
	}
	return parsed.String(), nil
}

func companionMessagesEndpoint(endpoint string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}
	switch {
	case strings.HasSuffix(parsed.Path, "/chat/completions"):
		parsed.Path = strings.TrimSuffix(parsed.Path, "/chat/completions") + "/messages"
	case strings.HasSuffix(parsed.Path, "/responses"):
		parsed.Path = strings.TrimSuffix(parsed.Path, "/responses") + "/messages"
	case strings.HasSuffix(parsed.Path, "/messages"):
	default:
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/messages"
	}
	return parsed.String(), nil
}

func prefersMessagesAPI(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return strings.HasSuffix(parsed.Path, "/messages")
}

func isRetryableEndpointError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "status 404") || strings.Contains(message, "status 405")
}

func buildPrompt(template string, cfg model.Config, report model.ValidationReport) string {
	type compactRule struct {
		ID            string   `json:"id"`
		Kind          string   `json:"kind"`
		Category      string   `json:"category"`
		Keywords      []string `json:"keywords,omitempty"`
		FieldPatterns []string `json:"field_patterns,omitempty"`
		Patterns      []string `json:"patterns,omitempty"`
		Validation    string   `json:"validation,omitempty"`
	}
	rules := make([]compactRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		rules = append(rules, compactRule{
			ID:            rule.ID,
			Kind:          rule.Kind,
			Category:      rule.Category,
			Keywords:      rule.Keywords,
			FieldPatterns: rule.FieldPatterns,
			Patterns:      rule.Patterns,
			Validation:    rule.Validation,
		})
	}
	ruleJSON, _ := json.MarshalIndent(rules, "", "  ")
	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	replacer := strings.NewReplacer(
		"{{RULES_JSON}}", string(ruleJSON),
		"{{VALIDATION_JSON}}", string(reportJSON),
	)
	return replacer.Replace(template)
}

func sanitizeJSONBlock(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
	}
	return strings.TrimSpace(content)
}
