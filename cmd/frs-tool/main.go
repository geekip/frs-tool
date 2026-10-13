package main

import (
	"context"
	"os"
	"os/signal"

	"frs-tool/internal/command"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(command.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, ""))
}
