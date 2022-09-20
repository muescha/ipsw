package logging

import (
	"fmt"
	"time"

	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/middleware"
	"github.com/caarlos0/log"
	"github.com/charmbracelet/lipgloss"
)

var (
	bold  = lipgloss.NewStyle().Bold(true)
	faint = lipgloss.NewStyle().Italic(true).Faint(true)
)

// Log pretty prints the given action and its title.
func Log(title string, next middleware.Action) middleware.Action {
	return func(ctx *context.Context) error {
		start := time.Now()
		defer func() {
			if took := time.Since(start).Round(time.Second); took > 0 {
				log.Info(faint.Render(fmt.Sprintf("took: %s", took)))
			}
			log.ResetPadding()
		}()
		log.Infof(bold.Render(title))
		log.IncreasePadding()
		return next(ctx)
	}
}

// PadLog pretty prints the given action and its title with an increased padding.
func PadLog(title string, next middleware.Action) middleware.Action {
	return func(ctx *context.Context) error {
		defer log.ResetPadding()
		log.IncreasePadding()
		log.Infof(bold.Render(title))
		log.IncreasePadding()
		return next(ctx)
	}
}
