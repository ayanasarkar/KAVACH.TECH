// Package pdf is a tiny dependency-free PDF writer (text, rules, filled boxes)
// using the 14 built-in base fonts, so the project builds offline.
package pdf

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	pageW, pageH = 595.28, 841.89 // A4 points
	marginX      = 50.0
	marginTop    = 60.0
	marginBottom = 55.0
)

// Doc builds a multi-page PDF with a flowing cursor.
type Doc struct {
	pages  []*bytes.Buffer
	cur    *bytes.Buffer
	y      float64
	Title  string
	Footer string
}

// New starts a document.
func New(title, footer string) *Doc {
	d := &Doc{Title: title, Footer: footer}
	d.newPage()
	return d
}

func (d *Doc) newPage() {
	d.cur = &bytes.Buffer{}
	d.pages = append(d.pages, d.cur)
	d.y = pageH - marginTop
}

func (d *Doc) ensure(h float64) {
	if d.y-h < marginBottom {
		d.newPage()
	}
}

// Break forces a new page.
func (d *Doc) Break() { d.newPage() }

// Space moves the cursor down.
func (d *Doc) Space(h float64) { d.y -= h }

func esc(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\' || r == '(' || r == ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 32:
		case r < 127:
			b.WriteRune(r)
		default:
			// WinAnsi (cp1252) for common punctuation, '?' otherwise.
			switch r {
			case '–':
				b.WriteString(`\226`)
			case '—':
				b.WriteString(`\227`)
			case '‘', '’':
				b.WriteString(`\222`)
			case '“', '”':
				b.WriteString(`\224`)
			case '•':
				b.WriteString(`\225`)
			case '…':
				b.WriteString(`\205`)
			case '→':
				b.WriteString(`->`)
			case '≥':
				b.WriteString(`>=`)
			case 'é':
				b.WriteString(`\351`)
			default:
				if r < 256 {
					fmt.Fprintf(&b, `\%03o`, r)
				} else {
					b.WriteByte('?')
				}
			}
		}
	}
	return b.String()
}

// approx Helvetica average glyph width factor.
func width(s string, size float64, bold bool) float64 {
	f := 0.50
	if bold {
		f = 0.54
	}
	return float64(len([]rune(s))) * size * f
}

func wrap(s string, size float64, maxW float64, bold bool, mono bool) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := ""
		w := func(x string) float64 {
			if mono {
				return float64(len([]rune(x))) * size * 0.6
			}
			return width(x, size, bold)
		}
		for _, wd := range words {
			for w(wd) > maxW { // hard-split very long tokens
				n := int(maxW / (size * 0.55))
				if n < 4 {
					n = 4
				}
				r := []rune(wd)
				if len(r) <= n {
					break
				}
				if line != "" {
					out = append(out, line)
					line = ""
				}
				out = append(out, string(r[:n]))
				wd = string(r[n:])
			}
			try := wd
			if line != "" {
				try = line + " " + wd
			}
			if w(try) > maxW && line != "" {
				out = append(out, line)
				line = wd
			} else {
				line = try
			}
		}
		out = append(out, line)
	}
	return out
}

// C builds a colour.
func C(r, g, b float64) RGB { return RGB{R: r, G: g, B: b} }

// RGB colour helper.
type RGB struct{ R, G, B float64 }

var (
	Black = RGB{0.1, 0.1, 0.12}
	Grey  = RGB{0.4, 0.4, 0.45}
	Navy  = RGB{0.07, 0.15, 0.3}
	White = RGB{1, 1, 1}
)

func (d *Doc) text(x, y float64, font string, size float64, c RGB, s string) {
	fmt.Fprintf(d.cur, "BT /%s %.1f Tf %.3f %.3f %.3f rg %.1f %.1f Td (%s) Tj ET\n", font, size, c.R, c.G, c.B, x, y, esc(s))
}

// Para writes wrapped text at the given indent.
func (d *Doc) Para(s string, size float64, bold bool, c RGB, indent float64) {
	font := "F1"
	if bold {
		font = "F2"
	}
	lines := wrap(s, size, pageW-2*marginX-indent, bold, false)
	lh := size * 1.35
	for _, l := range lines {
		d.ensure(lh)
		d.y -= lh
		if l != "" {
			d.text(marginX+indent, d.y, font, size, c, l)
		}
	}
}

// Mono writes wrapped monospaced text (evidence excerpts) on a light panel.
func (d *Doc) Mono(s string, size float64, indent float64) {
	lines := wrap(s, size, pageW-2*marginX-indent-12, false, true)
	lh := size * 1.3
	for _, l := range lines {
		d.ensure(lh + 2)
		d.rect(marginX+indent, d.y-lh+2, pageW-2*marginX-indent, lh, RGB{0.94, 0.95, 0.97})
		d.y -= lh
		d.text(marginX+indent+6, d.y+3, "F3", size, RGB{0.15, 0.15, 0.2}, l)
	}
	d.y -= 3
}

func (d *Doc) rect(x, y, w, h float64, c RGB) {
	fmt.Fprintf(d.cur, "%.3f %.3f %.3f rg %.1f %.1f %.1f %.1f re f\n", c.R, c.G, c.B, x, y, w, h)
}

// H1 section heading with a rule.
func (d *Doc) H1(s string) {
	d.ensure(40)
	d.Space(12)
	d.Para(s, 16, true, Navy, 0)
	d.rect(marginX, d.y-2, pageW-2*marginX, 1.2, Navy)
	d.Space(8)
}

// H2 sub-heading.
func (d *Doc) H2(s string) {
	d.ensure(30)
	d.Space(6)
	d.Para(s, 12, true, Black, 0)
	d.Space(2)
}

// Badge draws a coloured label inline at the current line start and returns nothing.
func (d *Doc) Badge(label string, c RGB) {
	d.ensure(18)
	w := width(label, 8.5, true) + 12
	d.rect(marginX, d.y-14, w, 13, c)
	d.text(marginX+6, d.y-11, "F2", 8.5, White, label)
	d.y -= 18
}

// Bar draws a labelled horizontal bar (severity distribution).
func (d *Doc) Bar(label string, n, max int, c RGB) {
	d.ensure(18)
	d.text(marginX, d.y-11, "F1", 10, Black, label)
	full := 300.0
	w := 0.0
	if max > 0 {
		w = full * float64(n) / float64(max)
	}
	d.rect(marginX+90, d.y-12, full, 11, RGB{0.9, 0.91, 0.93})
	if w > 0 {
		d.rect(marginX+90, d.y-12, w, 11, c)
	}
	d.text(marginX+90+full+8, d.y-11, "F2", 10, Black, fmt.Sprint(n))
	d.y -= 18
}

// Table draws a simple table with wrapped cells.
func (d *Doc) Table(head []string, rows [][]string, widths []float64) {
	size := 8.5
	draw := func(cells []string, bold bool, bg *RGB, fg RGB) {
		var cl [][]string
		maxL := 1
		for i, c := range cells {
			l := wrap(c, size, widths[i]-8, bold, false)
			cl = append(cl, l)
			if len(l) > maxL {
				maxL = len(l)
			}
		}
		h := float64(maxL)*size*1.3 + 6
		d.ensure(h)
		top := d.y
		x := marginX
		for i := range cells {
			if bg != nil {
				d.rect(x, top-h, widths[i], h, *bg)
			}
			f := "F1"
			if bold {
				f = "F2"
			}
			for k, ln := range cl[i] {
				d.text(x+4, top-size*1.3*float64(k+1)-1, f, size, fg, ln)
			}
			x += widths[i]
		}
		fmt.Fprintf(d.cur, "0.8 0.8 0.84 RG 0.5 w %.1f %.1f m %.1f %.1f l S\n", marginX, top-h, x, top-h)
		d.y = top - h
	}
	hb := Navy
	draw(head, true, &hb, White)
	for _, r := range rows {
		draw(r, false, nil, Black)
	}
	d.Space(6)
}

// Bytes renders the file.
func (d *Doc) Bytes() []byte {
	var out bytes.Buffer
	var offs []int
	obj := func(body string) int {
		offs = append(offs, out.Len())
		n := len(offs)
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
		return n
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	nPages := len(d.pages)
	kids := make([]string, nPages)
	for i := range kids {
		kids[i] = fmt.Sprintf("%d 0 R", 3+4+i*2)
	}
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), nPages))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")      // 3 F1
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>") // 4 F2
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")        // 5 F3
	obj(fmt.Sprintf("<< /Title (%s) /Producer (vapt-agent) >>", esc(d.Title)))                    // 6 info
	for i, p := range d.pages {
		content := p.String()
		foot := fmt.Sprintf("BT /F1 8 Tf 0.45 0.45 0.5 rg %.1f 28 Td (%s) Tj ET\nBT /F1 8 Tf 0.45 0.45 0.5 rg %.1f 28 Td (Page %d of %d) Tj ET\n", marginX, esc(d.Footer), pageW-marginX-55, i+1, nPages)
		content += foot
		pg := 7 + i*2
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>", pageW, pageH, pg+1))
		_ = pg
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offs)+1)
	for _, o := range offs {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offs)+1, xref)
	return out.Bytes()
}
