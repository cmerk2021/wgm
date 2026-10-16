package ui

import (
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Series is one line on a Graph.
type Series struct {
	Name   string
	Color  color.Color
	Values []float64
	Valid  []bool // gaps are drawn where Valid[i] is false
}

// Segment is a line segment in normalised coordinates: x and y in [0,1],
// y measured upward from the bottom.
type Segment struct{ X1, Y1, X2, Y2 float32 }

// Segments converts samples into line segments using a fixed horizontal
// slot count (so the graph scrolls smoothly) and the given vertical scale.
// Invalid samples break the line instead of being drawn as zero.
func Segments(values []float64, valid []bool, slots int, max float64) []Segment {
	if slots < 2 || max <= 0 {
		return nil
	}
	n := len(values)
	if n > slots {
		values = values[n-slots:]
		if len(valid) >= n {
			valid = valid[n-slots:]
		}
		n = slots
	}
	ok := func(i int) bool { return i < len(valid) && valid[i] && values[i] >= 0 }
	off := slots - n // right-align so the newest sample is at the right edge
	y := func(v float64) float32 {
		if v > max {
			v = max
		}
		return float32(v / max)
	}
	var out []Segment
	for i := 1; i < n; i++ {
		if !ok(i-1) || !ok(i) {
			continue
		}
		out = append(out, Segment{
			X1: float32(off+i-1) / float32(slots-1), Y1: y(values[i-1]),
			X2: float32(off+i) / float32(slots-1), Y2: y(values[i]),
		})
	}
	return out
}

// SeriesMax returns the largest valid value across series.
func SeriesMax(ss []Series) float64 {
	m := 0.0
	for _, s := range ss {
		for i, v := range s.Values {
			if i < len(s.Valid) && s.Valid[i] && v > m {
				m = v
			}
		}
	}
	return m
}

// Graph is a minimal multi-series line chart.
type Graph struct {
	widget.BaseWidget
	Slots  int
	Format func(float64) string
	Span   time.Duration // shown as the x-axis caption
	series []Series
}

// NewGraph creates a graph with the given number of horizontal slots.
func NewGraph(slots int, format func(float64) string) *Graph {
	g := &Graph{Slots: slots, Format: format}
	g.ExtendBaseWidget(g)
	return g
}

// SetSeries replaces the data and redraws.
func (g *Graph) SetSeries(ss []Series) {
	g.series = ss
	g.Refresh()
}

// CreateRenderer implements fyne.Widget.
func (g *Graph) CreateRenderer() fyne.WidgetRenderer {
	r := &graphRenderer{g: g}
	r.bg = canvas.NewRectangle(theme.Color(theme.ColorNameInputBackground))
	r.top = canvas.NewText("", theme.Color(theme.ColorNamePlaceHolder))
	r.top.TextSize = theme.CaptionTextSize()
	r.legend = canvas.NewText("", theme.Color(theme.ColorNameForeground))
	r.legend.TextSize = theme.CaptionTextSize()
	r.span = canvas.NewText("", theme.Color(theme.ColorNamePlaceHolder))
	r.span.TextSize = theme.CaptionTextSize()
	r.span.Alignment = fyne.TextAlignTrailing
	return r
}

type graphRenderer struct {
	g                 *Graph
	bg                *canvas.Rectangle
	top, legend, span *canvas.Text
	grid              []*canvas.Line
	lines             []*canvas.Line
	size              fyne.Size
}

func (r *graphRenderer) Layout(s fyne.Size) {
	r.size = s
	r.Refresh()
}

func (r *graphRenderer) MinSize() fyne.Size { return fyne.NewSize(240, 120) }

func (r *graphRenderer) Refresh() {
	s := r.size
	r.bg.FillColor = theme.Color(theme.ColorNameInputBackground)
	r.bg.Resize(s)
	max := NiceCeil(SeriesMax(r.g.series) * 1.1)
	format := r.g.Format
	if format == nil {
		format = func(v float64) string { return FormatRate(v, true) }
	}
	r.top.Text = "max " + format(max)
	r.top.Move(fyne.NewPos(4, 2))
	legend := ""
	for i, se := range r.g.series {
		if i > 0 {
			legend += "   "
		}
		legend += "— " + se.Name
	}
	r.legend.Text = legend
	r.legend.Move(fyne.NewPos(4, s.Height-r.legend.MinSize().Height-2))
	if r.g.Span > 0 {
		r.span.Text = "last " + FormatDuration(r.g.Span)
	}
	r.span.Resize(fyne.NewSize(s.Width-4, r.span.MinSize().Height))
	r.span.Move(fyne.NewPos(0, s.Height-r.span.MinSize().Height-2))

	pad := r.top.MinSize().Height + 4
	plotH := s.Height - 2*pad
	if plotH < 10 {
		plotH = 10
	}
	if len(r.grid) == 0 {
		for i := 0; i < 3; i++ {
			l := canvas.NewLine(theme.Color(theme.ColorNameSeparator))
			l.StrokeWidth = 1
			r.grid = append(r.grid, l)
		}
	}
	for i, l := range r.grid {
		y := pad + plotH*float32(i)/2
		l.Position1, l.Position2 = fyne.NewPos(0, y), fyne.NewPos(s.Width, y)
	}

	n := 0
	for _, se := range r.g.series {
		for _, sg := range Segments(se.Values, se.Valid, r.g.Slots, max) {
			if n >= len(r.lines) {
				r.lines = append(r.lines, canvas.NewLine(se.Color))
			}
			l := r.lines[n]
			l.StrokeColor = se.Color
			l.StrokeWidth = 2
			l.Hidden = false
			l.Position1 = fyne.NewPos(sg.X1*s.Width, pad+plotH*(1-sg.Y1))
			l.Position2 = fyne.NewPos(sg.X2*s.Width, pad+plotH*(1-sg.Y2))
			n++
		}
	}
	for ; n < len(r.lines); n++ {
		r.lines[n].Hidden = true
	}
	canvas.Refresh(r.g)
}

func (r *graphRenderer) Objects() []fyne.CanvasObject {
	objs := []fyne.CanvasObject{r.bg}
	for _, l := range r.grid {
		objs = append(objs, l)
	}
	for _, l := range r.lines {
		objs = append(objs, l)
	}
	return append(objs, r.top, r.legend, r.span)
}

func (r *graphRenderer) Destroy() {}
