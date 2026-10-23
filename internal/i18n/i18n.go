// Package i18n resolves every user-visible string from message catalogs.
//
// Catalogs are embedded JSON files in locales/, one per language, named by
// BCP 47 tag (en.json, de.json, …). Each maps a message key to either a
// string, which may contain fmt verbs, or an object with plural forms
// ("one", "other", optionally "zero", "two", "few", "many") selected by the
// first argument. English is the fallback for missing keys and languages.
// Adding a language means adding one file.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/message/catalog"
)

//go:embed locales/*.json
var files embed.FS

// Catalog holds all languages.
type Catalog struct {
	cat     *catalog.Builder
	tags    []language.Tag
	matcher language.Matcher
	keys    map[string]bool // keys of the English catalog
}

// Load reads the embedded catalogs.
func Load() (*Catalog, error) {
	b := catalog.NewBuilder(catalog.Fallback(language.English))
	c := &Catalog{cat: b, keys: map[string]bool{}}
	entries, err := files.ReadDir("locales")
	if err != nil {
		return nil, err
	}
	// English first so that it is the matcher's default.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() == "en.json" || (entries[j].Name() != "en.json" && entries[i].Name() < entries[j].Name())
	})
	for _, e := range entries {
		tag, err := language.Parse(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", e.Name(), err)
		}
		data, err := files.ReadFile(path.Join("locales", e.Name()))
		if err != nil {
			return nil, err
		}
		var msgs map[string]json.RawMessage
		if err := json.Unmarshal(data, &msgs); err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", e.Name(), err)
		}
		for key, raw := range msgs {
			if err := c.set(tag, key, raw); err != nil {
				return nil, fmt.Errorf("i18n: %s: %s: %w", e.Name(), key, err)
			}
			if tag == language.English {
				c.keys[key] = true
			}
		}
		c.tags = append(c.tags, tag)
	}
	c.matcher = language.NewMatcher(c.tags)
	return c, nil
}

var pluralForms = []string{"zero", "one", "two", "few", "many", "other"}

func (c *Catalog) set(tag language.Tag, key string, raw json.RawMessage) error {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return c.cat.SetString(tag, key, s)
	}
	var forms map[string]string
	if err := json.Unmarshal(raw, &forms); err != nil {
		return err
	}
	if forms["other"] == "" {
		return fmt.Errorf("plural message without \"other\"")
	}
	var cases []any
	for _, f := range pluralForms {
		if v, ok := forms[f]; ok {
			sel := f
			if f == "zero" {
				sel = "=0"
			}
			cases = append(cases, sel, v)
		}
	}
	return c.cat.Set(tag, key, plural.Selectf(1, "%d", cases...))
}

// Has reports whether key exists in the English catalog.
func (c *Catalog) Has(key string) bool { return c.keys[key] }

// Keys returns all English message keys.
func (c *Catalog) Keys() []string {
	out := make([]string, 0, len(c.keys))
	for k := range c.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Languages lists the available catalog languages.
func (c *Catalog) Languages() []language.Tag { return c.tags }

// Printer formats messages for one language.
type Printer struct {
	p   *message.Printer
	Tag language.Tag
	cat *Catalog
}

// Match picks the best language for an Accept-Language header or an explicit
// choice; it falls back to English.
func (c *Catalog) Match(prefs ...string) *Printer {
	var tags []language.Tag
	for _, p := range prefs {
		if p == "" {
			continue
		}
		t, _, err := language.ParseAcceptLanguage(p)
		if err == nil {
			tags = append(tags, t...)
		}
	}
	tag := language.English
	if len(tags) > 0 {
		_, idx, conf := c.matcher.Match(tags...)
		if conf != language.No {
			tag = c.tags[idx]
		}
	}
	return &Printer{p: message.NewPrinter(tag, message.Catalog(c.cat)), Tag: tag, cat: c}
}

// T translates key with optional arguments. Unknown keys are returned in
// brackets so that they stand out instead of failing a page.
func (p *Printer) T(key string, args ...any) string {
	if !p.cat.keys[key] {
		return "[" + key + "]"
	}
	return p.p.Sprintf(key, args...)
}
