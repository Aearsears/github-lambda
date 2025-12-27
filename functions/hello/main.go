package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/github-lambda/pkg/lambda"
)

// Input represents the expected input for this function.
type Input struct {
	Name string `json:"name"`
}

// Output represents the response from this function.
type Output struct {
	Message string `json:"message"`
}

func handler(ctx context.Context, event lambda.Event) (lambda.Response, error) {
	var input Input
	if err := json.Unmarshal(event.Payload, &input); err != nil {
		return lambda.Error(400, "Invalid input: "+err.Error()), nil
	}

	if input.Name == "" {
		input.Name = "World"
	}

	output := Output{
		Message: fmt.Sprintf("Hello, %s!", input.Name),
	}

	return lambda.Success(output), nil
}

func main() {
	// Register the handler
	lambda.RegisterFunc("hello", handler)

	// In GitHub Actions context, read event from environment/file
	eventJSON := os.Getenv("LAMBDA_EVENT")
	if eventJSON == "" {
		fmt.Println("No LAMBDA_EVENT provided")
		os.Exit(1)
	}

	var event lambda.Event
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		fmt.Printf("Failed to parse event: %v\n", err)
		os.Exit(1)
	}

	h, err := lambda.DefaultRegistry.Get(event.FunctionName)
	if err != nil {
		fmt.Printf("Handler not found: %v\n", err)
		os.Exit(1)
	}

	ctx := lambda.NewContext(context.Background(), event.InvocationID, event.FunctionName, 0)
	response, err := h.Handle(ctx, event)
	if err != nil {
		fmt.Printf("Handler error: %v\n", err)
		os.Exit(1)
	}

	output, _ := json.Marshal(response)
	fmt.Println(string(output))

	// Write to GitHub Actions output
	if outputFile := os.Getenv("GITHUB_OUTPUT"); outputFile != "" {
		f, _ := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0644)
		defer f.Close()
		fmt.Fprintf(f, "result=%s\n", string(output))
	}
}
