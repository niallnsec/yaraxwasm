package yaraxwasm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	version, err := Version()
	assert.NoError(t, err)
	assert.NotEmpty(t, version)
}

func TestNamespaces(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.NewNamespace("foo")
	assert.NoError(t, c.AddSource("rule test { condition: true }"))
	c.NewNamespace("bar")
	assert.NoError(t, c.AddSource("rule test { condition: true }"))

	s := NewScanner(c.Build())
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 2)
}

func TestGlobals(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)
	x := map[string]any{"a": map[string]any{"a": "b"}, "b": "d"}
	y := []any{"z"}

	assert.NoError(t, c.DefineGlobal("test_hashmap", x))
	assert.NoError(t, c.DefineGlobal("A", "b"))
	assert.NoError(t, c.DefineGlobal("test_arr", y))

	assert.NoError(t, c.AddSource("rule test {condition: test_hashmap.a.a == \"b\"}"))
	assert.NoError(t, c.AddSource("rule test2 {condition: A == \"b\"}"))
	assert.NoError(t, c.AddSource("rule test3 {condition: test_arr[0] == \"z\"}"))

	s := NewScanner(c.Build())
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 3)

	assert.NoError(t, s.SetGlobal("A", "c"))
	assert.NoError(t, s.SetGlobal("test_arr", []any{"f"}))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestUnsupportedModules(t *testing.T) {
	r, err := Compile(`
		import "unsupported_module"
		rule test { condition: true }`,
		IgnoreModule("unsupported_module"))

	assert.NoError(t, err)
	scanResults, _ := r.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestBannedModules(t *testing.T) {
	_, err := Compile(
		`import "pe"`,
		BanModule("pe", "pe module is banned", "pe module was used here"))

	expected := `error[E100]: pe module is banned
 --> line:1:1
  |
1 | import "pe"
  | ^^^^^^^^^^^ pe module was used here`
	assert.EqualError(t, err, expected)
}

func TestCompileCleansUpTemporaryCompilerGuest(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	require.NoError(t, Initialise())

	countGuests := func() int {
		if sharedGuestProgram == nil {
			return 0
		}
		sharedGuestProgram.host.guestsMu.RLock()
		defer sharedGuestProgram.host.guestsMu.RUnlock()
		return len(sharedGuestProgram.host.guests)
	}

	baseline := countGuests()

	rules, err := Compile(`rule ok { condition: true }`)
	require.NoError(t, err)
	defer rules.Destroy()
	assert.Equal(t, baseline, countGuests())

	_, err = Compile(`rule broken { condition: foo }`)
	require.Error(t, err)
	assert.True(t, containsUnknownIdentifier(err))
	assert.Equal(t, baseline, countGuests())
}

func TestCompileReturnsTypedCompileError(t *testing.T) {
	_, err := Compile(`rule broken { condition: foo }`)

	var compileErr *CompileError
	assert.ErrorAs(t, err, &compileErr)
	if assert.NotNil(t, compileErr) {
		assert.Equal(t, CompileErrorTypeUnknownIdentifier, compileErr.Type)
		assert.True(t, compileErr.HasCode(CompileErrorCodeUnknownIdentifier))
	}
	assert.ErrorIs(t, err, &CompileError{Type: CompileErrorTypeUnknownIdentifier})
}

func TestDisabledIncludes(t *testing.T) {
	_, err := Compile(
		`include "foo.yar"`, EnableIncludes(false))

	expected := `error[E044]: include statements not allowed
 --> line:1:1
  |
1 | include "foo.yar"
  | ^^^^^^^^^^^^^^^^^ includes are disabled for this compilation`
	assert.EqualError(t, err, expected)
}

func TestIncludes(t *testing.T) {
	includeDir := filepath.Join(".tmp", t.Name())
	err := os.MkdirAll(includeDir, 0o755)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(includeDir)
	})

	file, err := os.CreateTemp(includeDir, "prefix")
	assert.NoError(t, err)
	assert.NoError(t, file.Close())

	absIncludePath, err := filepath.Abs(file.Name())
	assert.NoError(t, err)
	includePath := strings.TrimLeft(filepath.ToSlash(absIncludePath), "/")

	_, err = Compile(fmt.Sprintf(`include "%s"`, includePath))

	assert.NoError(t, err)
}

func TestIncludeDirResolvesRelativeIncludes(t *testing.T) {
	includeDir := t.TempDir()
	includePath := filepath.Join(includeDir, "shared.yar")
	err := os.WriteFile(includePath, []byte(`rule shared { condition: true }`), 0o600)
	require.NoError(t, err)

	rules, err := Compile(`
		include "shared.yar"
		rule root { condition: shared }
	`, IncludeDir(includeDir))
	require.NoError(t, err)
	defer rules.Destroy()

	results, err := rules.Scan(nil)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 2)
	assert.Equal(t, "shared", results.MatchingRules()[0].Identifier())
	assert.Equal(t, "root", results.MatchingRules()[1].Identifier())
}

func TestRelaxedReSyntax(t *testing.T) {
	r, err := Compile(`
		rule test { strings: $a = /\Release/ condition: $a }`,
		RelaxedReSyntax(true))
	assert.NoError(t, err)
	scanResults, _ := r.Scan([]byte("Release"))
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestConditionOptimization(t *testing.T) {
	_, err := Compile(`
		rule test { condition: true }`,
		ConditionOptimization(true))
	assert.NoError(t, err)
}

func TestErrorOnSlowPattern(t *testing.T) {
	_, err := Compile(`
		rule test { strings: $a = /a.*/ condition: $a }`,
		ErrorOnSlowPattern(true))
	assert.Error(t, err)
}

func TestErrorOnSlowLoop(t *testing.T) {
	_, err := Compile(`
		rule test { condition: for all x in (0..filesize): (x == 0) }`,
		ErrorOnSlowLoop(true))
	assert.Error(t, err)
}

func TestSerialization(t *testing.T) {
	r, err := Compile("rule test { condition: true }")
	assert.NoError(t, err)

	var buf bytes.Buffer

	// Write rules into buffer
	n, err := r.WriteTo(&buf)

	assert.NoError(t, err)
	assert.Len(t, buf.Bytes(), int(n))

	// Read rules from buffer
	r, _ = ReadFrom(&buf)

	// Make sure the rules work properly.
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestRulesRemainUsableAfterCompilerDestroy(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	err = c.AddSource(`
		import "pe"
		rule test : tag {
			meta:
				name = "portable"
			condition:
				true
		}`)
	assert.NoError(t, err)

	rules := c.Build()
	c.Destroy()
	defer rules.Destroy()

	assert.Equal(t, 1, rules.Count())
	assert.Equal(t, []string{"pe"}, rules.Imports())

	slice := rules.Slice()
	assert.Len(t, slice, 1)
	assert.Equal(t, "test", slice[0].Identifier())
	assert.Equal(t, []string{"tag"}, slice[0].Tags())
	assert.Equal(t, "portable", slice[0].Metadata()[0].Value())

	var buf bytes.Buffer
	_, err = rules.WriteTo(&buf)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.Bytes())

	results, err := rules.Scan([]byte{})
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestReadFromProducesPortableRules(t *testing.T) {
	compiled, err := Compile(`
		import "elf"
		rule test {
			meta:
				payload = "\x01\x02"
			condition:
				true
		}`)
	assert.NoError(t, err)

	var buf bytes.Buffer
	_, err = compiled.WriteTo(&buf)
	assert.NoError(t, err)
	compiled.Destroy()

	rules, err := ReadFrom(bytes.NewReader(buf.Bytes()))
	assert.NoError(t, err)
	defer rules.Destroy()

	imports := rules.Imports()
	assert.Equal(t, []string{"elf"}, imports)
	imports[0] = "mutated"
	assert.Equal(t, []string{"elf"}, rules.Imports())

	slice := rules.Slice()
	assert.Len(t, slice, 1)
	assert.Equal(t, []byte{0x01, 0x02}, slice[0].Metadata()[0].Value())

	tags := slice[0].Tags()
	assert.Empty(t, tags)
	slice[0].Metadata()[0].Value().([]byte)[0] = 0xff

	refetched := rules.Slice()
	assert.Equal(t, []byte{0x01, 0x02}, refetched[0].Metadata()[0].Value())

	for range 3 {
		scanner := NewScanner(rules)
		results, err := scanner.Scan([]byte{})
		scanner.Destroy()
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}
}

func TestVariables(t *testing.T) {
	r, _ := Compile(
		"rule test { condition: var == 1234 }",
		Globals(map[string]any{"var": 1234}))

	scanResults, _ := NewScanner(r).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.NoError(t, c.DefineGlobal("var", 1234))
	assert.NoError(t, c.AddSource("rule test { condition: var == 1234 }"))
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, c.DefineGlobal("var", -1234))
	assert.NoError(t, c.AddSource("rule test { condition: var == -1234 }"))
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, c.DefineGlobal("var", true))
	assert.NoError(t, c.AddSource("rule test { condition: var }"))
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, c.DefineGlobal("var", false))
	assert.NoError(t, c.AddSource("rule test { condition: var }"))
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 0)

	assert.NoError(t, c.DefineGlobal("var", "foo"))
	assert.NoError(t, c.AddSource("rule test { condition: var == \"foo\" }"))
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, c.DefineGlobal("var", 3.4))
	assert.NoError(t, c.AddSource("rule test { condition: var == 3.4 }"))
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	err = c.DefineGlobal("var", struct{}{})
	assert.EqualError(t, err, "variable `var` has unsupported type: struct {}")
}

func TestError(t *testing.T) {
	_, err := Compile("rule test { condition: foo }")
	expected := `error[E009]: unknown identifier ` + "`foo`" + `
 --> line:1:24
  |
1 | rule test { condition: foo }
  |                        ^^^ this identifier has not been declared`
	assert.EqualError(t, err, expected)
}

func TestCompilerFeatures(t *testing.T) {
	rules := `import "test_proto2" rule test { condition: test_proto2.requires_foo_and_bar }`

	_, err := Compile(rules)
	assert.EqualError(t, err, `error[E100]: foo is required
 --> line:1:57
  |
1 | import "test_proto2" rule test { condition: test_proto2.requires_foo_and_bar }
  |                                                         ^^^^^^^^^^^^^^^^^^^^ this field was used without foo`)

	_, err = Compile(rules, WithFeature("foo"))
	assert.EqualError(t, err, `error[E100]: bar is required
 --> line:1:57
  |
1 | import "test_proto2" rule test { condition: test_proto2.requires_foo_and_bar }
  |                                                         ^^^^^^^^^^^^^^^^^^^^ this field was used without bar`)

	_, err = Compile(rules, WithFeature("foo"), WithFeature("bar"))
	assert.NoError(t, err)
}

func TestCompilerLinters(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.NoError(t, c.AddRuleNameLinter("^r_.+", false))
	assert.NoError(t, c.AddTagsAllowedLinter([]string{"foo", "bar"}, false))
	assert.NoError(t, c.AddTagRegexLinter("^(foo|bar)", false))
	assert.NoError(t, c.AddRequiredMetadataLinter("author", false))

	err = c.AddSource(`rule bad : baz {
		strings:
			$a = "foo"
		condition:
			$a
	}`)
	assert.NoError(t, err)

	warnings := c.Warnings()
	assert.Len(t, warnings, 4)
	assert.Equal(t, "invalid_rule_name", warnings[0].Code)
	assert.Equal(t, "unknown_tag", warnings[1].Code)
	assert.Equal(t, "invalid_tag", warnings[2].Code)
	assert.Equal(t, "missing_metadata", warnings[3].Code)
}

func TestCompilerLinterOptions(t *testing.T) {
	c, err := NewCompiler(
		RuleNameLinter("^r_.+", false),
		RequiredMetadataLinter("author", false),
	)
	assert.NoError(t, err)

	err = c.AddSource(`rule bad { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)

	warnings := c.Warnings()
	assert.Len(t, warnings, 2)
	assert.Equal(t, "invalid_rule_name", warnings[0].Code)
	assert.Equal(t, "missing_metadata", warnings[1].Code)
}

func TestCompilerTagLinterOptions(t *testing.T) {
	c, err := NewCompiler(
		TagsAllowedLinter([]string{"foo", "bar"}, false),
		TagRegexLinter("^(foo|bar)$", false),
	)
	assert.NoError(t, err)

	err = c.AddSource(`rule r_ok : baz { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)

	warnings := c.Warnings()
	assert.Len(t, warnings, 2)
	assert.Equal(t, WarningCodeUnknownTag, warnings[0].CodeID())
	assert.Equal(t, WarningCodeInvalidTag, warnings[1].CodeID())
}

func TestCompilerLinterInvalidRegex(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.Error(t, c.AddRuleNameLinter("(foo", false))
	assert.Error(t, c.AddTagRegexLinter("(bar", false))
}

func TestCompilerLintersPersistAfterBuild(t *testing.T) {
	c, err := NewCompiler(RuleNameLinter("^r_.+", false))
	assert.NoError(t, err)

	assert.NoError(t, c.AddSource(`rule r_ok { strings: $a = "foo" condition: $a }`))
	rules := c.Build()
	rules.Destroy()

	assert.NoError(t, c.AddSource(`rule bad { strings: $a = "foo" condition: $a }`))
	warnings := c.Warnings()
	assert.Len(t, warnings, 1)
	assert.Equal(t, "invalid_rule_name", warnings[0].Code)
}

func TestEmitWasmFile(t *testing.T) {
	c, err := NewCompiler(RuleNameLinter("^r_.+", false))
	assert.NoError(t, err)

	assert.NoError(t, c.AddSource(`rule r_emit { strings: $a = "foo" condition: $a }`))

	file, err := os.CreateTemp(t.TempDir(), "yarax-emit-*.wasm")
	assert.NoError(t, err)
	path := file.Name()
	assert.NoError(t, file.Close())

	assert.NoError(t, c.EmitWasmFile(path))

	data, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(data), 4)
	assert.Equal(t, []byte{0x00, 0x61, 0x73, 0x6d}, data[:4])

	assert.NoError(t, c.AddSource(`rule bad { strings: $a = "foo" condition: $a }`))
	warnings := c.Warnings()
	assert.Len(t, warnings, 1)
	assert.Equal(t, "invalid_rule_name", warnings[0].Code)
}

func TestDiagnosticHelpers(t *testing.T) {
	compileErr := CompileError{
		Type:  CompileErrorTypeUnknownIdentifier,
		Code:  string(CompileErrorCodeUnknownIdentifier),
		Title: "unknown identifier `foo`",
	}
	assert.Equal(t, CompileErrorCodeUnknownIdentifier, compileErr.CodeID())
	assert.True(t, compileErr.HasType(CompileErrorTypeUnknownIdentifier))
	assert.False(t, compileErr.HasType(CompileErrorTypeUnknownTag))
	assert.True(t, compileErr.HasCode(CompileErrorCodeUnknownIdentifier))
	assert.False(t, compileErr.HasCode(CompileErrorCodeUnknownTag))
	assert.True(t, compileErr.Is(&CompileError{Type: CompileErrorTypeUnknownIdentifier}))
	assert.True(t, compileErr.Is(CompileError{Code: string(CompileErrorCodeUnknownIdentifier)}))
	assert.True(t, compileErr.Is(&CompileError{Title: "unknown identifier `foo`"}))
	assert.False(t, compileErr.Is(&CompileError{}))
	assert.False(t, compileErr.Is(&CompileError{Type: CompileErrorTypeUnknownTag}))
	var nilTarget *CompileError
	assert.False(t, compileErr.Is(nilTarget))

	warning := Warning{
		Type: WarningTypeSlowPattern,
		Code: string(WarningCodeSlowPattern),
	}
	assert.Equal(t, WarningCodeSlowPattern, warning.CodeID())
	assert.True(t, warning.HasType(WarningTypeSlowPattern))
	assert.False(t, warning.HasType(WarningTypeUnknownTag))
	assert.True(t, warning.HasCode(WarningCodeSlowPattern))
	assert.False(t, warning.HasCode(WarningCodeUnknownTag))
}

func TestErrors(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.NoError(t, c.AddSource("rule test_1 { condition: true }"))
	assert.Equal(t, []CompileError{}, c.Errors())

	assert.Equal(t, []Warning{
		{
			Type:   WarningTypeInvariantBooleanExpression,
			Code:   "invariant_expr",
			Title:  "invariant boolean expression",
			Line:   1,
			Column: 26,
			Labels: []Label{
				{
					Level:  "warning",
					Line:   1,
					Column: 26,
					Span:   Span{Start: 25, End: 29},
					Text:   "this expression is always true",
				},
			},
			Footers: []Footer{
				{
					Level: "note",
					Text:  "rule `test_1` is always `true`",
				},
			},
			Text: `warning[invariant_expr]: invariant boolean expression
 --> line:1:26
  |
1 | rule test_1 { condition: true }
  |                          ---- this expression is always true
  |
  = note: rule ` + "`test_1` is always `true`",
		},
	}, c.Warnings())

	err = c.AddSource("rule test_2 { condition: foo }", WithOrigin("test.yar"))
	assert.Error(t, err)
	assert.Equal(t, []CompileError{
		{
			Type:   CompileErrorTypeUnknownIdentifier,
			Code:   "E009",
			Title:  "unknown identifier `foo`",
			Line:   1,
			Column: 26,
			Labels: []Label{
				{
					Level:      "error",
					CodeOrigin: "test.yar",
					Line:       1,
					Column:     26,
					Span:       Span{Start: 25, End: 28},
					Text:       "this identifier has not been declared",
				},
			},
			Footers: []Footer{},
			Text: `error[E009]: unknown identifier ` + "`foo`" + `
 --> test.yar:1:26
  |
1 | rule test_2 { condition: foo }
  |                          ^^^ this identifier has not been declared`,
		},
	}, c.Errors())
}

func TestRules(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.NoError(t, c.AddSource(`rule test_1 : tag1 tag2 {
      condition:
        true
	}`))

	assert.NoError(t, c.AddSource(`rule test_2 {
      meta:
        foo = "foo"
        bar = 1
        baz = "\x00\x01"
        qux = true
      condition:
        true
	}`))

	rules := c.Build()
	assert.Equal(t, 2, rules.Count())

	slice := rules.Slice()
	assert.Len(t, slice, 2)
	assert.Equal(t, "test_1", slice[0].Identifier())
	assert.Equal(t, "test_2", slice[1].Identifier())

	assert.Equal(t, "default", slice[0].Namespace())
	assert.Equal(t, "default", slice[1].Namespace())

	assert.Equal(t, []string{"tag1", "tag2"}, slice[0].Tags())
	assert.Equal(t, []string{}, slice[1].Tags())

	assert.Len(t, slice[0].Metadata(), 0)
	assert.Len(t, slice[1].Metadata(), 4)

	assert.Equal(t, "foo", slice[1].Metadata()[0].Identifier())
	assert.Equal(t, "foo", slice[1].Metadata()[0].Value().(string))

	assert.Equal(t, "bar", slice[1].Metadata()[1].Identifier())
	assert.Equal(t, int64(1), slice[1].Metadata()[1].Value().(int64))

	assert.Equal(t, "baz", slice[1].Metadata()[2].Identifier())
	assert.Equal(t, []byte{0x00, 0x01}, slice[1].Metadata()[2].Value().([]byte))

	assert.Equal(t, "qux", slice[1].Metadata()[3].Identifier())
	assert.Equal(t, true, slice[1].Metadata()[3].Value().(bool))
}

func TestImportsIter(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.NoError(t, c.AddSource(`
	import "pe"
	import "elf"
	rule test {
			condition:
				true
	}`))

	rules := c.Build()
	imports := rules.Imports()

	assert.Len(t, imports, 2)
	assert.Equal(t, "pe", imports[0])
	assert.Equal(t, "elf", imports[1])
}

func TestWarnings(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	assert.NoError(t, c.AddSource("rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }"))

	assert.Equal(t, []Warning{
		{
			Type:   WarningTypeConsecutiveJumps,
			Code:   "consecutive_jumps",
			Title:  "consecutive jumps in hex pattern `$a`",
			Line:   1,
			Column: 31,
			Labels: []Label{
				{
					Level:      "warning",
					CodeOrigin: "",
					Line:       1,
					Column:     31,
					Span:       Span{Start: 30, End: 40},
					Text:       "these consecutive jumps will be treated as [0-2]",
				},
			},
			Footers: []Footer{},
			Text: `warning[consecutive_jumps]: consecutive jumps in hex pattern ` + "`$a`" + `
 --> line:1:31
  |
1 | rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
  |                               ---------- these consecutive jumps will be treated as [0-2]
  |
help: consider the following change
  |
1 - rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
1 + rule test { strings: $a = {01 [0-2] 02 } condition: $a }
  |`,
		},
		{
			Type:   WarningTypeSlowPattern,
			Code:   "slow_pattern",
			Title:  "slow pattern",
			Line:   1,
			Column: 27,
			Labels: []Label{
				{
					Level:      "warning",
					CodeOrigin: "",
					Line:       1,
					Column:     27,
					Span:       Span{Start: 26, End: 45},
					Text:       "this pattern may slow down the scan",
				},
			},
			Footers: []Footer{},
			Text: `warning[slow_pattern]: slow pattern
 --> line:1:27
  |
1 | rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
  |                           ------------------- this pattern may slow down the scan`,
		},
	}, c.Warnings())
}
