package config

import (
	"os"
	"strings"
	"testing"
)

func TestSetValues(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		edits          []Edit
	}{
		{"double quoted", "general:\n  listen: \":8443\"\n", "general:\n  listen: \":9443\"\n",
			[]Edit{{"general", "listen", ":9443"}}},
		{"single quoted with comment", "general:\n  listen: ':8443'   # https\n", "general:\n  listen: \":9443\"   # https\n",
			[]Edit{{"general", "listen", ":9443"}}},
		{"plain with comment", "crl:\n  listen: 127.0.0.1:8080 # off: \"\"\n", "crl:\n  listen: \"127.0.0.1:9080\" # off: \"\"\n",
			[]Edit{{"crl", "listen", "127.0.0.1:9080"}}},
		{"escaped quote", "general:\n  password_hash: \"a\\\"b\"  # x\n", "general:\n  password_hash: \"$argon2id$v=19$a/b\"  # x\n",
			[]Edit{{"general", "password_hash", "$argon2id$v=19$a/b"}}},
		{"empty value", "general:\n  listen:\n  data_dir: d\n", "general:\n  listen: \":1\"\n  data_dir: d\n",
			[]Edit{{"general", "listen", ":1"}}},
		{"empty value with comment", "general:\n  listen: # later\n", "general:\n  listen: \":1\" # later\n",
			[]Edit{{"general", "listen", ":1"}}},
		{"missing key", "general:\n    data_dir: d # x\ncrl:\n  listen: \"\"\n", "general:\n    listen: \":1\"\n    data_dir: d # x\ncrl:\n  listen: \"\"\n",
			[]Edit{{"general", "listen", ":1"}}},
		{"empty section", "general:\n  data_dir: d\ncrl:\ndatabases: []\n", "general:\n  data_dir: d\ncrl:\n  listen: \":2\"\ndatabases: []\n",
			[]Edit{{"crl", "listen", ":2"}}},
		{"missing section", "general:\n  data_dir: d", "general:\n  data_dir: d\ncrl:\n  base_urls: \"x\"\n  listen: \":2\"\n",
			[]Edit{{"crl", "listen", ":2"}, {"crl", "base_urls", "x"}}},
		{"flow section", "# “quoted” …\ngeneral: {}\n", "",
			[]Edit{{"general", "listen", ":1"}}},
	} {
		got, err := SetValues([]byte(tc.in), tc.edits)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: no error, got %q", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		} else if string(got) != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// The shipped configurations keep everything but the edited lines.
func TestSetValuesShipped(t *testing.T) {
	for _, file := range []string{"../../config.example.yaml", "../../packaging/linux/config.yaml"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		out, err := SetValues(b, []Edit{
			{"general", "listen", "127.0.0.1:443"},
			{"general", "password_hash", "$argon2id$v=19$x"},
			{"crl", "listen", ""},
		})
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		before, after := strings.Split(string(b), "\n"), strings.Split(string(out), "\n")
		if len(before) != len(after) {
			t.Fatalf("%s: %d lines, was %d", file, len(after), len(before))
		}
		changed := 0
		for i := range before {
			if before[i] != after[i] {
				changed++
			}
		}
		if changed != 3 {
			t.Errorf("%s: %d lines changed, want 3:\n%s", file, changed, out)
		}
		c, err := Parse(out, t.TempDir())
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if c.General.Listen != "127.0.0.1:443" || c.General.PasswordHash != "$argon2id$v=19$x" || c.CRL.ListenAddr() != "" {
			t.Errorf("%s: general = %+v, crl = %q", file, c.General, c.CRL.ListenAddr())
		}
	}
}

func TestNewFile(t *testing.T) {
	c, err := Parse(NewFile(":9443", "", "$argon2id$x"), "/srv")
	if err != nil {
		t.Fatal(err)
	}
	if c.General.DataDir != "/srv/data" || c.General.Listen != ":9443" || c.General.PasswordHash != "$argon2id$x" || c.CRL.ListenAddr() != "" {
		t.Fatalf("config = %+v %q", c.General, c.CRL.ListenAddr())
	}
}
