package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// makeKiroTool 构造一个工具 wrapper，desc 为给定描述，schema 为给定 JSON 对象。
func makeKiroTool(name, desc string, schema map[string]interface{}) KiroToolWrapper {
	w := KiroToolWrapper{}
	w.ToolSpecification.Name = name
	w.ToolSpecification.Description = desc
	w.ToolSpecification.InputSchema = InputSchema{JSON: schema}
	return w
}

// schemaWithDescriptions 造一个靠 description/examples 撑大的 schema，用于验证简化能
// 剥掉这些说明性字段、显著减小体积。刻意不带 enum——enum 属于“保留”字段（见
// TestSimplifyToolSchemaPreservesConstraints），混进来会让本类“简化即达标”的体积断言
// 受 enum 保留量干扰。
func schemaWithDescriptions(propCount int, descPerProp string) map[string]interface{} {
	props := make(map[string]interface{}, propCount)
	for i := 0; i < propCount; i++ {
		key := "field" + strings.Repeat("x", 3) + string(rune('a'+i%26)) + string(rune('0'+i%10))
		props[key] = map[string]interface{}{
			"type":        "string",
			"description": descPerProp,
			"examples":    []interface{}{descPerProp, descPerProp},
			"title":       descPerProp,
		}
	}
	return map[string]interface{}{
		"type":       "object",
		"required":   []interface{}{"fieldxxxa0"},
		"properties": props,
	}
}

func TestCompressToolsNoOpUnderThreshold(t *testing.T) {
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "")
	tools := []KiroToolWrapper{
		makeKiroTool("smallTool", "a short description", map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"x": map[string]interface{}{"type": "string"}},
		}),
	}
	before, _ := json.Marshal(tools)
	out := compressToolsIfNeeded(tools)
	after, _ := json.Marshal(out)
	if string(before) != string(after) {
		t.Fatalf("expected no-op under threshold\nbefore=%s\nafter=%s", before, after)
	}
}

func TestCompressToolsSchemaSimplificationBringsUnderThreshold(t *testing.T) {
	// 阈值设小，让“简化 schema”这一步就足以达标，验证不会进入 description 截断。
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "2048")
	desc := "keep me readable" // 短描述，简化 schema 后总量应已达标
	tools := []KiroToolWrapper{
		makeKiroTool("bigSchemaTool", desc, schemaWithDescriptions(40, strings.Repeat("verbose ", 20))),
	}
	if estimateToolsBytes(tools) <= 2048 {
		t.Fatalf("precondition: tools should exceed threshold before compression")
	}

	out := compressToolsIfNeeded(tools)

	if got := estimateToolsBytes(out); got > 2048 {
		t.Fatalf("expected size <= threshold after schema simplification, got %d", got)
	}
	// description 未被截断（schema 简化已足够）。
	if out[0].ToolSpecification.Description != desc {
		t.Fatalf("description should be intact when schema simplification suffices, got %q", out[0].ToolSpecification.Description)
	}
	// 简化后：结构骨架保留，说明性字段剥离。
	schema := out[0].ToolSpecification.InputSchema.JSON.(map[string]interface{})
	if schema["type"] != "object" {
		t.Fatalf("top-level type must be preserved")
	}
	if _, ok := schema["required"]; !ok {
		t.Fatalf("required must be preserved")
	}
	props := schema["properties"].(map[string]interface{})
	for name, p := range props {
		pm := p.(map[string]interface{})
		if pm["type"] != "string" {
			t.Fatalf("prop %s type must be preserved", name)
		}
		if _, ok := pm["description"]; ok {
			t.Fatalf("prop %s description must be stripped", name)
		}
		if _, ok := pm["enum"]; ok {
			t.Fatalf("prop %s enum must be stripped", name)
		}
		if _, ok := pm["examples"]; ok {
			t.Fatalf("prop %s examples must be stripped", name)
		}
	}
}

func TestCompressToolsTruncatesDescriptionWhenSchemaNotEnough(t *testing.T) {
	// 阈值极小，简化 schema 仍不够 → 必须截断 description；验证保底字符数与 UTF-8 安全。
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "200")
	longDesc := strings.Repeat("用途说明", 200) // 多字节字符，验证不切坏 rune
	tools := []KiroToolWrapper{
		makeKiroTool("toolWithLongDesc", longDesc, schemaWithDescriptions(10, "x")),
	}

	out := compressToolsIfNeeded(tools)

	gotDesc := out[0].ToolSpecification.Description
	if len([]rune(gotDesc)) >= len([]rune(longDesc)) {
		t.Fatalf("description should be truncated")
	}
	if len([]rune(gotDesc)) < minToolDescChars {
		t.Fatalf("description must keep at least %d chars, got %d", minToolDescChars, len([]rune(gotDesc)))
	}
	// UTF-8 安全：截断结果仍是合法字符串（rune 往返一致）。
	if string([]rune(gotDesc)) != gotDesc {
		t.Fatalf("truncation broke UTF-8 boundary")
	}
}

func TestCompressToolsDisabledByZeroThreshold(t *testing.T) {
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "0")
	tools := []KiroToolWrapper{
		makeKiroTool("bigTool", "d", schemaWithDescriptions(40, strings.Repeat("verbose ", 20))),
	}
	before, _ := json.Marshal(tools)
	out := compressToolsIfNeeded(tools)
	after, _ := json.Marshal(out)
	if string(before) != string(after) {
		t.Fatalf("threshold=0 must disable compression (pass-through)")
	}
}

func TestResolveToolsSizeThreshold(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{"empty falls back to default", "", defaultToolsSizeThreshold},
		{"explicit zero disables", "0", 0},
		{"valid override", "4096", 4096},
		{"negative falls back", "-1", defaultToolsSizeThreshold},
		{"garbage falls back", "abc", defaultToolsSizeThreshold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", tc.env)
			if got := resolveToolsSizeThreshold(); got != tc.want {
				t.Fatalf("env=%q want %d got %d", tc.env, tc.want, got)
			}
		})
	}
}

// TestCompressToolsEndToEndViaConvertClaude 验证压缩已接到 Claude 工具转换路径：
// 构造少量但 schema 臃肿的工具，经 convertClaudeTools 后体积应被显著压缩。
// 注意：对齐 kiro-rs，压缩是“尽力而为”——简化 schema + 截断 description 两步后即返回，
// 不保证一定降到阈值内（工具数量本身极多时可能仍超），故这里断言“显著变小”而非“必达阈值”。
func TestCompressToolsEndToEndViaConvertClaude(t *testing.T) {
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "2048")
	claudeTools := make([]ClaudeTool, 0, 4)
	for i := 0; i < 4; i++ {
		claudeTools = append(claudeTools, ClaudeTool{
			Name:        "tool" + string(rune('A'+i%26)) + string(rune('0'+i%10)),
			Description: "a tool",
			InputSchema: schemaWithDescriptions(8, strings.Repeat("verbose ", 16)),
		})
	}

	// 不经压缩时的体积（关掉压缩量一次基线）。
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "0")
	rawWrappers, _ := convertClaudeTools(claudeTools)
	rawBytes := estimateToolsBytes(rawWrappers)

	// 开启压缩。
	t.Setenv("KIRO_TOOLS_COMPRESS_THRESHOLD_BYTES", "2048")
	wrappers, _ := convertClaudeTools(claudeTools)
	got := estimateToolsBytes(wrappers)

	if got > 2048 {
		t.Fatalf("少量臃肿工具应被压到阈值内，got %d bytes", got)
	}
	if got >= rawBytes {
		t.Fatalf("压缩后应显著小于原始体积：raw=%d compressed=%d", rawBytes, got)
	}
}

// TestSimplifyToolSchemaPreservesConstraints 锁定 code review 发现的高危回归：简化
// schema 时必须保留 type/required/enum 及 $ref/anyOf/oneOf/allOf，且嵌套 object 的
// required 不能丢——否则“压缩”反而把原本能过的请求改成上游拒收。
func TestSimplifyToolSchemaPreservesConstraints(t *testing.T) {
	schema := map[string]interface{}{
		"type":     "object",
		"required": []interface{}{"mode", "addr"},
		"properties": map[string]interface{}{
			// 枚举约束必须保留（模型据此选值）。
			"mode": map[string]interface{}{
				"type":        "string",
				"enum":        []interface{}{"r", "w"},
				"description": "should be stripped",
			},
			// 嵌套 object：其 required 与子属性 type 必须保留。
			"addr": map[string]interface{}{
				"type":     "object",
				"required": []interface{}{"host"},
				"properties": map[string]interface{}{
					"host": map[string]interface{}{"type": "string", "description": "drop me"},
					"port": map[string]interface{}{"type": "integer"},
				},
			},
			// 只有 $ref、无 type：不能被压成 {}，$ref 必须保留。
			"ref": map[string]interface{}{
				"$ref":        "#/$defs/Foo",
				"description": "drop me",
			},
			// anyOf 子 schema 需递归简化但保留结构。
			"choice": map[string]interface{}{
				"anyOf": []interface{}{
					map[string]interface{}{"type": "string", "description": "drop"},
					map[string]interface{}{"type": "null"},
				},
			},
		},
	}

	out := simplifyToolSchema(schema).(map[string]interface{})

	// 顶层 required 保留。
	if req, _ := out["required"].([]interface{}); len(req) != 2 {
		t.Fatalf("top-level required must be preserved, got %v", out["required"])
	}
	props := out["properties"].(map[string]interface{})

	// enum 保留、description 剥离。
	mode := props["mode"].(map[string]interface{})
	if _, ok := mode["enum"]; !ok {
		t.Fatal("enum must be preserved (model needs it to pick valid values)")
	}
	if _, ok := mode["description"]; ok {
		t.Fatal("description must be stripped")
	}

	// 嵌套 object 的 required 保留。
	addr := props["addr"].(map[string]interface{})
	if req, _ := addr["required"].([]interface{}); len(req) != 1 {
		t.Fatalf("nested object required must be preserved, got %v", addr["required"])
	}
	addrProps := addr["properties"].(map[string]interface{})
	if addrProps["host"].(map[string]interface{})["type"] != "string" {
		t.Fatal("nested property type must be preserved")
	}
	if _, ok := addrProps["host"].(map[string]interface{})["description"]; ok {
		t.Fatal("nested property description must be stripped")
	}

	// 只有 $ref 的节点不能塌成空对象。
	ref := props["ref"].(map[string]interface{})
	if ref["$ref"] != "#/$defs/Foo" {
		t.Fatalf("$ref must be preserved to avoid empty {} node, got %v", ref)
	}
	if len(ref) == 0 {
		t.Fatal("ref node collapsed to empty object — model/upstream cannot interpret it")
	}

	// anyOf 保留且子 schema 简化。
	choice := props["choice"].(map[string]interface{})
	anyOf, ok := choice["anyOf"].([]interface{})
	if !ok || len(anyOf) != 2 {
		t.Fatalf("anyOf must be preserved with its subschemas, got %v", choice)
	}
	if anyOf[0].(map[string]interface{})["type"] != "string" {
		t.Fatal("anyOf subschema type must survive simplification")
	}
	if _, ok := anyOf[0].(map[string]interface{})["description"]; ok {
		t.Fatal("anyOf subschema description must be stripped")
	}
}

// TestTruncateDescByRatioCJKSafe 验证 CJK 描述按字节比例截断、不切坏 rune、保底字符数。
func TestTruncateDescByRatioCJKSafe(t *testing.T) {
	desc := strings.Repeat("中文说明", 100) // 1200 bytes (每字 3B), 400 runes
	got := truncateDescByRatio(desc, 0.25)

	// 结果合法 UTF-8、未切坏 rune。
	if string([]rune(got)) != got {
		t.Fatal("truncation broke a multi-byte rune boundary")
	}
	// 比原文短。
	if len(got) >= len(desc) {
		t.Fatalf("expected truncation, got %d >= %d bytes", len(got), len(desc))
	}
	// 保底字符数。
	if len([]rune(got)) < minToolDescChars {
		t.Fatalf("must keep at least %d chars, got %d", minToolDescChars, len([]rune(got)))
	}
}
