package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kiro-go/logger"
)

// ==================== Tool-call XML Leak Fix ====================
//
// 背景：Kiro 后端偶尔把模型的工具调用 XML（<function_calls>/<invoke>/<parameter>，
//       <function_calls> 有时被损坏成纯文本 "count"）当成普通文本，混在
//       assistantResponseEvent 里【流式分帧】发出。我们原先对文本零过滤，导致：
//       原始 XML 泄漏成可见文本，且客户端解析不到工具调用 → 工具不执行、任务中断。
//
// 方案：用有状态的跨帧过滤器分离「正常文本」与「泄漏的工具调用」；正常文本照常输出，
//       泄漏工具解析为结构化 tool_use 暂存；流结束时与已见的结构化 toolUseEvent 去重
//       （同名同参丢弃，避免重复执行）后注入救回。
//
// 开关：环境变量 KIRO_TOOL_LEAK_FIX=off 可回退到无过滤直通；
//       KIRO_TOOL_LEAK_DEBUG=1 打印命中调试日志。

var (
	invokeRe         = regexp.MustCompile(`(?s)<invoke name="([^"]+)">(.*?)</invoke>`)
	parameterRe      = regexp.MustCompile(`(?s)<parameter name="([^"]+)">(.*?)</parameter>`)
	fcOpenTailRe     = regexp.MustCompile(`<function_calls>\s*$`)
	countTailRe      = regexp.MustCompile(`count\s*$`)
	countOpenTailRe  = regexp.MustCompile(`(?s)count\s*<.*$`)
	fcCloseLeadingRe = regexp.MustCompile(`^\s*</function_calls>`)
	intRe            = regexp.MustCompile(`^-?\d+$`)
	floatRe          = regexp.MustCompile(`^-?\d*\.\d+$`)
)

// leakToolMarkers are the partial tag prefixes we may need to hold back at a
// frame boundary so a tag split across frames isn't emitted as visible text.
var leakToolMarkers = []string{
	"<function_calls>",
	"<invoke name=",
	"</invoke>",
	"</function_calls>",
	"<parameter name=",
	"</parameter>",
	"count",
}

type leakedTool struct {
	name  string
	input map[string]interface{}
}

// toolLeakFilter holds the cross-frame state for separating leaked tool-call
// XML from normal assistant text.
type toolLeakFilter struct {
	enabled    bool
	debug      bool
	carry      string
	leaked     []leakedTool
	seen       map[string]bool
	idCounter  int
}

func newToolLeakFilter() *toolLeakFilter {
	enabled := strings.ToLower(strings.TrimSpace(os.Getenv("KIRO_TOOL_LEAK_FIX"))) != "off"
	return &toolLeakFilter{
		enabled: enabled,
		debug:   os.Getenv("KIRO_TOOL_LEAK_DEBUG") == "1",
		seen:    make(map[string]bool),
	}
}

// toolSig builds a stable name+input signature for dedup. Go's json.Marshal
// sorts map keys, so equal name+input always produce the same string.
func toolSig(name string, input map[string]interface{}) string {
	data, err := json.Marshal(input)
	if err != nil {
		return name + "|?"
	}
	return name + "|" + string(data)
}

// markSeen records a structured tool_use signature so a later leaked copy with
// identical name+input is deduplicated instead of re-executed.
func (f *toolLeakFilter) markSeen(name string, input map[string]interface{}) {
	if f == nil || !f.enabled {
		return
	}
	f.seen[toolSig(name, input)] = true
}

// parseInvokeBody turns a single <invoke> body into a structured tool input,
// restoring bool/number/null types while preserving raw strings (keeps internal
// whitespace for fields like command/old_string).
func parseInvokeBody(name, body string) leakedTool {
	input := make(map[string]interface{})
	for _, m := range parameterRe.FindAllStringSubmatch(body, -1) {
		key := m[1]
		raw := m[2]
		t := strings.TrimSpace(raw)
		switch {
		case t == "true":
			input[key] = true
		case t == "false":
			input[key] = false
		case t == "null":
			input[key] = nil
		case intRe.MatchString(t):
			if n, err := strconv.Atoi(t); err == nil {
				input[key] = n
			} else {
				input[key] = raw
			}
		case floatRe.MatchString(t):
			if fv, err := strconv.ParseFloat(t, 64); err == nil {
				input[key] = fv
			} else {
				input[key] = raw
			}
		default:
			input[key] = raw
		}
	}
	return leakedTool{name: name, input: input}
}

// stripToolPrefix removes a trailing "<function_calls>" or corrupted "count"
// marker that immediately precedes a tool-call block.
func stripToolPrefix(pre string) string {
	if loc := fcOpenTailRe.FindStringIndex(pre); loc != nil {
		return pre[:loc[0]]
	}
	if loc := countTailRe.FindStringIndex(pre); loc != nil {
		return pre[:loc[0]]
	}
	return pre
}

// hasOpenInvoke reports whether the carry ends with an unclosed <invoke>.
func hasOpenInvoke(s string) bool {
	i := strings.LastIndex(s, "<invoke name=")
	if i == -1 {
		return false
	}
	return !strings.Contains(s[i:], "</invoke>")
}

// pendingToolTail returns how many trailing bytes of s might be the start of a
// tool-call tag (split across frames) and should be held back from emission.
// Markers are ASCII, so byte-wise suffix matching is safe even when s contains
// multibyte UTF-8 (a multibyte tail can't equal an ASCII prefix).
func pendingToolTail(s string) int {
	hold := 0
	for _, tag := range leakToolMarkers {
		maxK := len(tag) - 1
		if len(s) < maxK {
			maxK = len(s)
		}
		for k := maxK; k >= 1; k-- {
			if s[len(s)-k:] == tag[:k] {
				if k > hold {
					hold = k
				}
				break
			}
		}
	}
	if loc := countTailRe.FindStringIndex(s); loc != nil {
		if l := len(s) - loc[0]; l > hold {
			hold = l
		}
	}
	if loc := countOpenTailRe.FindStringIndex(s); loc != nil {
		if l := len(s) - loc[0]; l > hold {
			hold = l
		}
	}
	return hold
}

// process drains the carry buffer: normal text goes to emit, leaked tool calls
// are parsed into f.leaked. When isFlush is true any residual is emitted as-is.
func (f *toolLeakFilter) process(isFlush bool, emit func(string)) {
	out := func(s string) {
		if s == "" {
			return
		}
		emit(s)
	}

	// Extract every fully-closed <invoke> block.
	for {
		fi := strings.Index(f.carry, "<invoke name=")
		if fi == -1 {
			break
		}
		rel := strings.Index(f.carry[fi:], "</invoke>")
		if rel == -1 {
			break // not closed yet, wait for more frames
		}
		ci := fi + rel

		out(stripToolPrefix(f.carry[:fi]))

		sub := f.carry[fi:]
		locs := invokeRe.FindAllStringSubmatchIndex(sub, -1)
		consumedEnd := ci + len("</invoke>")
		for _, loc := range locs {
			absStart := fi + loc[0]
			if absStart > consumedEnd+30 {
				break
			}
			name := sub[loc[2]:loc[3]]
			body := sub[loc[4]:loc[5]]
			tool := parseInvokeBody(name, body)
			f.leaked = append(f.leaked, tool)
			if f.debug {
				preview, _ := json.Marshal(tool.input)
				p := string(preview)
				if len(p) > 120 {
					p = p[:120]
				}
				logger.Debugf("[tool-leak-fix] parsed leaked tool: %s %s", tool.name, p)
			}
			consumedEnd = fi + loc[1]
		}

		if loc := fcCloseLeadingRe.FindStringIndex(f.carry[consumedEnd:]); loc != nil {
			consumedEnd += loc[1]
		}
		f.carry = f.carry[consumedEnd:]
	}

	if hasOpenInvoke(f.carry) {
		if isFlush {
			// Stream ended with an unclosed invoke = corrupted tool call;
			// emit as text rather than dropping characters.
			out(f.carry)
			f.carry = ""
			return
		}
		oi := strings.Index(f.carry, "<invoke name=")
		safe := stripToolPrefix(f.carry[:oi])
		out(safe)
		f.carry = f.carry[len(safe):]
		return
	}

	if isFlush {
		out(f.carry)
		f.carry = ""
		return
	}

	hold := pendingToolTail(f.carry)
	out(f.carry[:len(f.carry)-hold])
	f.carry = f.carry[len(f.carry)-hold:]
}

// injectLeaked emits the rescued leaked tools at stream end, deduplicated
// against structured tool_use events already seen (same name+input dropped).
func (f *toolLeakFilter) injectLeaked(cb *KiroStreamCallback) {
	if len(f.leaked) == 0 {
		return
	}
	rescued, deduped := 0, 0
	for _, lt := range f.leaked {
		sig := toolSig(lt.name, lt.input)
		if f.seen[sig] {
			deduped++
			continue
		}
		f.seen[sig] = true
		f.idCounter++
		id := fmt.Sprintf("toolleakfix_%s_%d", strconv.FormatInt(time.Now().UnixNano(), 36), f.idCounter)
		if cb != nil && cb.OnToolUse != nil {
			cb.OnToolUse(KiroToolUse{ToolUseID: id, Name: lt.name, Input: lt.input})
		}
		rescued++
	}
	if rescued > 0 || f.debug {
		logger.Infof("[Kiro] Tool-leak-fix: leaked=%d rescued=%d deduped=%d", len(f.leaked), rescued, deduped)
	}
}
