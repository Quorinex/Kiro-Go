package rtk

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultMinBytes = 500
	DefaultMaxBytes = 10 * 1024 * 1024
	detectWindow    = 1024
)

type Config struct {
	Enabled  bool
	MinBytes int
	MaxBytes int
}

type Stats struct {
	BytesBefore int
	BytesAfter  int
	Hits        []Hit
}

type Hit struct {
	Shape  string
	Filter string
	Saved  int
}

func DefaultConfig() Config {
	return Config{Enabled: true, MinBytes: DefaultMinBytes, MaxBytes: DefaultMaxBytes}
}

func (cfg Config) normalized() Config {
	if cfg.MinBytes <= 0 {
		cfg.MinBytes = DefaultMinBytes
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MinBytes > cfg.MaxBytes {
		cfg.MinBytes = DefaultMinBytes
		cfg.MaxBytes = DefaultMaxBytes
	}
	return cfg
}

func TransformJSON(raw []byte, cfg Config) ([]byte, Stats, bool, error) {
	cfg = cfg.normalized()
	if !cfg.Enabled {
		return raw, Stats{}, false, nil
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, Stats{}, false, err
	}
	stats, changed := TransformValue(payload, cfg)
	if !changed {
		return raw, stats, false, nil
	}
	updated, err := json.Marshal(payload)
	if err != nil {
		return nil, stats, false, err
	}
	return updated, stats, true, nil
}

func TransformValue(payload any, cfg Config) (Stats, bool) {
	cfg = cfg.normalized()
	if !cfg.Enabled {
		return Stats{}, false
	}
	var stats Stats
	cmds := toolCommands(payload)
	changed := compressValue(payload, cfg, &stats, "", cmds)
	return stats, changed
}

func FormatLog(stats Stats) string {
	if len(stats.Hits) == 0 {
		return ""
	}
	filters := map[string]bool{}
	saved := 0
	for _, hit := range stats.Hits {
		filters[hit.Filter] = true
		saved += hit.Saved
	}
	names := make([]string, 0, len(filters))
	for name := range filters {
		names = append(names, name)
	}
	sort.Strings(names)
	pct := "0.0"
	if stats.BytesBefore > 0 {
		pct = strconv.FormatFloat(float64(saved)*100/float64(stats.BytesBefore), 'f', 1, 64)
	}
	return "[RTK] saved " + stringInt(saved) + "B / " + stringInt(stats.BytesBefore) + "B (" + pct + "%) via [" + strings.Join(names, ",") + "] hits=" + stringInt(len(stats.Hits))
}

func compressValue(v any, cfg Config, stats *Stats, shape string, cmds map[string]string) bool {
	switch val := v.(type) {
	case map[string]any:
		changed := false
		if typeName, _ := val["type"].(string); typeName == "function_call_output" {
			cmd := lookupCommand(cmds, val, "call_id")
			if next, ok := compressContent(val["output"], cfg, stats, "openai-responses", cmd, cmds); ok {
				val["output"] = next
				changed = true
			}
		}
		if role, _ := val["role"].(string); role == "tool" {
			cmd := lookupCommand(cmds, val, "tool_call_id")
			if next, ok := compressContent(val["content"], cfg, stats, "openai-tool", cmd, cmds); ok {
				val["content"] = next
				changed = true
			}
		}
		if typeName, _ := val["type"].(string); typeName == "tool_result" && val["is_error"] != true {
			cmd := lookupCommand(cmds, val, "tool_use_id")
			if next, ok := compressContent(val["content"], cfg, stats, "tool-result", cmd, cmds); ok {
				val["content"] = next
				changed = true
			}
		}
		if _, ok := val["toolUseId"].(string); ok {
			status, _ := val["status"].(string)
			if !strings.EqualFold(strings.TrimSpace(status), "error") {
				if next, ok := compressKiroResultContent(val["content"], cfg, stats, "kiro-tool-result", "", cmds); ok {
					val["content"] = next
					changed = true
				}
			}
		}
		for _, child := range val {
			changed = compressValue(child, cfg, stats, shape, cmds) || changed
		}
		return changed
	case []any:
		changed := false
		for _, child := range val {
			changed = compressValue(child, cfg, stats, shape, cmds) || changed
		}
		return changed
	default:
		return false
	}
}

func lookupCommand(cmds map[string]string, m map[string]any, key string) string {
	if cmds == nil {
		return ""
	}
	id, _ := m[key].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return cmds[id]
}

func compressContent(v any, cfg Config, stats *Stats, shape, command string, cmds map[string]string) (any, bool) {
	switch val := v.(type) {
	case string:
		out, ok := compressText(val, cfg, stats, shape, command)
		return out, ok
	case []any:
		changed := false
		for i, item := range val {
			switch part := item.(type) {
			case string:
				if out, ok := compressText(part, cfg, stats, shape, command); ok {
					val[i] = out
					changed = true
				}
			case map[string]any:
				if text, ok := part["text"].(string); ok {
					if out, compressed := compressText(text, cfg, stats, shape, command); compressed {
						part["text"] = out
						changed = true
					}
				}
				changed = compressValue(part, cfg, stats, shape, cmds) || changed
			}
		}
		return val, changed
	default:
		return v, false
	}
}

func compressKiroResultContent(v any, cfg Config, stats *Stats, shape, command string, cmds map[string]string) (any, bool) {
	arr, ok := v.([]any)
	if !ok {
		return v, false
	}
	changed := false
	for _, item := range arr {
		part, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if text, ok := part["text"].(string); ok {
			if out, compressed := compressText(text, cfg, stats, shape, command); compressed {
				part["text"] = out
				changed = true
			}
		}
		changed = compressValue(part, cfg, stats, shape, cmds) || changed
	}
	return arr, changed
}

func compressText(text string, cfg Config, stats *Stats, shape, command string) (string, bool) {
	bytesIn := len([]byte(text))
	if bytesIn < cfg.MinBytes || bytesIn > cfg.MaxBytes {
		return text, false
	}
	out, filter := autoFilterCommand(text, command)
	if out == "" || filter == "" {
		return text, false
	}
	bytesOut := len([]byte(out))
	if bytesOut <= 0 || bytesOut >= bytesIn {
		return text, false
	}
	stats.BytesBefore += bytesIn
	stats.BytesAfter += bytesOut
	stats.Hits = append(stats.Hits, Hit{Shape: shape, Filter: filter, Saved: bytesIn - bytesOut})
	return out, true
}

func autoFilterCommand(text, command string) (string, string) {
	head := text
	if len(head) > detectWindow {
		head = head[:detectWindow]
	}
	gitAllowed := true
	if strings.TrimSpace(command) != "" {
		if name := filterForCommand(command); name != "" {
			if out, ok := applyNamedFilter(name, text); ok && len([]byte(out)) < len([]byte(text)) {
				return out, name
			}
		}
		gitAllowed = commandIsGit(command)
	}
	switch {
	case gitAllowed && (strings.Contains(head, "diff --git ") || strings.Contains(head, "\n@@ ")):
		return compactGitDiff(text), "git-diff"
	case gitAllowed && (strings.Contains(head, "On branch ") || strings.Contains(head, "Untracked files:") || looksLikePorcelain(head)):
		return compactGitStatus(text), "git-status"
	case looksLikeBuildOutput(head):
		return compactBuildOutput(text), "build-output"
	case looksLikeGrep(head):
		return compactGrep(text), "grep"
	case looksLikePathList(head):
		return compactFind(text), "find"
	case strings.Contains(head, "\u251c\u2500\u2500") || strings.Contains(head, "\u2514\u2500\u2500") || strings.Contains(head, "\u2502  "):
		return compactTree(text), "tree"
	case looksLikeLS(head):
		return compactLS(text), "ls"
	case searchListHeaderRE.MatchString(head):
		return compactSearchList(text), "search-list"
	case isLineNumbered(strings.Split(head, "\n")):
		return readNumbered(text), "read-numbered"
	case len(strings.Split(text, "\n")) >= 250:
		return smartTruncate(text), "smart-truncate"
	case len(nonEmptyLines(text)) >= 5:
		return dedupLog(text), "dedup-log"
	default:
		return "", ""
	}
}

func applyNamedFilter(name, text string) (string, bool) {
	switch name {
	case "git-diff":
		return compactGitDiff(text), true
	case "git-status":
		return compactGitStatus(text), true
	case "build-output":
		return compactBuildOutput(text), true
	case "grep":
		return compactGrep(text), true
	case "find":
		return compactFind(text), true
	case "ls":
		return compactLS(text), true
	case "tree":
		return compactTree(text), true
	case "search-list":
		return compactSearchList(text), true
	case "read-numbered":
		return readNumbered(text), true
	case "smart-truncate":
		return smartTruncate(text), true
	case "dedup-log":
		return dedupLog(text), true
	default:
		return "", false
	}
}

func compactGitDiff(diff string) string {
	const maxLines = 500
	const maxHunkLines = 100
	var result []string
	currentFile := ""
	added, removed := 0, 0
	inHunk := false
	hunkShown, hunkSkipped := 0, 0
	truncated := false
	flushSkipped := func() {
		if hunkSkipped > 0 {
			result = append(result, "  ... ("+stringInt(hunkSkipped)+" lines truncated)")
			truncated = true
			hunkSkipped = 0
		}
	}
	flushFile := func() {
		flushSkipped()
		if currentFile != "" {
			result = append(result, "summary: "+currentFile+" +"+stringInt(added)+" -"+stringInt(removed))
		}
		added, removed = 0, 0
	}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			flushFile()
			currentFile = strings.TrimSpace(line)
			result = append(result, line)
			inHunk = false
			continue
		}
		if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "new file") || strings.HasPrefix(line, "deleted file") {
			result = append(result, line)
			continue
		}
		if strings.HasPrefix(line, "@@") {
			flushSkipped()
			result = append(result, line)
			inHunk = true
			hunkShown = 0
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added++
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			removed++
		}
		if inHunk {
			if hunkShown < maxHunkLines || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
				result = append(result, line)
				hunkShown++
			} else {
				hunkSkipped++
			}
			continue
		}
		result = append(result, line)
		if len(result) >= maxLines {
			truncated = true
			break
		}
	}
	flushFile()
	if len(result) > maxLines {
		result = result[:maxLines]
		truncated = true
	}
	if truncated {
		result = append(result, "[diff truncated]")
	}
	return strings.TrimRight(strings.Join(result, "\n"), "\n")
}

func compactGrep(text string) string {
	const perFileMax = 10
	byFile := map[string][]grepMatch{}
	for _, line := range nonEmptyLines(text) {
		first := strings.Index(line, ":")
		if first < 0 {
			continue
		}
		second := strings.Index(line[first+1:], ":")
		if second < 0 {
			continue
		}
		second += first + 1
		file := line[:first]
		lineNum := line[first+1 : second]
		if _, err := strconv.Atoi(lineNum); err != nil {
			continue
		}
		byFile[file] = append(byFile[file], grepMatch{lineNum: lineNum, content: line[second+1:]})
	}
	if len(byFile) == 0 {
		return text
	}
	files := make([]string, 0, len(byFile))
	total := 0
	for f, matches := range byFile {
		files = append(files, f)
		total += len(matches)
	}
	sort.Strings(files)
	out := []string{stringInt(total) + " matches in " + stringInt(len(files)) + " files:", ""}
	for _, file := range files {
		matches := byFile[file]
		out = append(out, "[file] "+file+" ("+stringInt(len(matches))+"):")
		limit := perFileMax
		if len(matches) < limit {
			limit = len(matches)
		}
		for _, item := range matches[:limit] {
			out = append(out, "  "+leftPad(item.lineNum, 4)+": "+strings.TrimSpace(item.content))
		}
		if len(matches) > limit {
			out = append(out, "  +"+stringInt(len(matches)-limit))
		}
		out = append(out, "")
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

type grepMatch struct {
	lineNum string
	content string
}

func compactFind(text string) string {
	return compactPathBasenames(nonEmptyLines(text), 10, 20)
}

func compactPathBasenames(paths []string, perDirMax, maxDirs int) string {
	groups := map[string][]string{}
	for _, p := range paths {
		dir := "."
		name := p
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			dir = p[:idx]
			if dir == "" {
				dir = "/"
			}
			name = p[idx+1:]
		}
		groups[dir] = append(groups[dir], name)
	}
	dirs := make([]string, 0, len(groups))
	for dir := range groups {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	out := []string{stringInt(len(paths)) + " files in " + stringInt(len(dirs)) + " dirs:", ""}
	for i, dir := range dirs {
		if i >= maxDirs {
			out = append(out, "+"+stringInt(len(dirs)-i)+" more dirs")
			break
		}
		names := groups[dir]
		out = append(out, dir+"/ ("+stringInt(len(names))+"):")
		limit := perDirMax
		if len(names) < limit {
			limit = len(names)
		}
		for _, name := range names[:limit] {
			out = append(out, "  "+name)
		}
		if len(names) > limit {
			out = append(out, "  +"+stringInt(len(names)-limit))
		}
		out = append(out, "")
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func compactGitStatus(text string) string {
	const maxFiles = 10
	const maxUntracked = 10
	branch := ""
	var stagedFiles, modifiedFiles, untrackedFiles []string
	staged, modified, untracked, conflicts := 0, 0, 0, 0
	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if strings.HasPrefix(raw, "On branch ") {
			branch = strings.Fields(strings.TrimPrefix(raw, "On branch "))[0]
			continue
		}
		if strings.HasPrefix(raw, "##") {
			branch = strings.TrimSpace(strings.TrimPrefix(raw, "##"))
			continue
		}
		if len(raw) >= 4 && strings.Contains(" MADRCU?!", raw[:1]) && strings.Contains(" MADRCU?!", raw[1:2]) && raw[2] == ' ' {
			x, y := raw[0], raw[1]
			file := raw[3:]
			if x != ' ' && x != '?' {
				staged++
				if len(stagedFiles) < maxFiles {
					stagedFiles = append(stagedFiles, file)
				}
			}
			if y != ' ' && y != '?' {
				modified++
				if len(modifiedFiles) < maxFiles {
					modifiedFiles = append(modifiedFiles, file)
				}
			}
			if x == '?' || y == '?' {
				untracked++
				if len(untrackedFiles) < maxUntracked {
					untrackedFiles = append(untrackedFiles, file)
				}
			}
			if x == 'U' || y == 'U' {
				conflicts++
			}
			continue
		}
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "modified:") {
			modified++
			if len(modifiedFiles) < maxFiles {
				modifiedFiles = append(modifiedFiles, strings.TrimSpace(strings.TrimPrefix(t, "modified:")))
			}
			continue
		}
		if strings.HasPrefix(t, "new file:") {
			staged++
			if len(stagedFiles) < maxFiles {
				stagedFiles = append(stagedFiles, strings.TrimSpace(strings.TrimPrefix(t, "new file:")))
			}
			continue
		}
		if !strings.Contains(t, " ") && strings.Contains(t, "/") {
			untracked++
			if len(untrackedFiles) < maxUntracked {
				untrackedFiles = append(untrackedFiles, t)
			}
		}
	}
	var out []string
	if branch != "" {
		out = append(out, "branch: "+branch)
	}
	out = append(out, "staged="+stringInt(staged)+" modified="+stringInt(modified)+" untracked="+stringInt(untracked)+" conflicts="+stringInt(conflicts))
	appendList := func(label string, files []string, total int) {
		if total == 0 {
			return
		}
		out = append(out, label+":")
		for _, f := range files {
			out = append(out, "  "+f)
		}
		if total > len(files) {
			out = append(out, "  +"+stringInt(total-len(files)))
		}
	}
	appendList("staged files", stagedFiles, staged)
	appendList("modified files", modifiedFiles, modified)
	appendList("untracked files", untrackedFiles, untracked)
	return strings.Join(out, "\n")
}

func compactBuildOutput(input string) string {
	lines := strings.Split(input, "\n")
	var errors, warnings, deprecations []string
	summary := ""
	compilingCount, downloadingCount := 0, 0
	inCargoError := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if inCargoError {
			if trimmed == "" {
				inCargoError = false
				continue
			}
			if cargoErrContRE.MatchString(line) {
				errors = append(errors, line)
				continue
			}
			inCargoError = false
		}
		if trimmed == "" {
			continue
		}
		switch {
		case npmErrorRE.MatchString(trimmed), yarnErrorRE.MatchString(trimmed), strings.HasPrefix(trimmed, "ERROR:"), errorLineRE.MatchString(trimmed), strings.HasPrefix(trimmed, "error -->"), buildFailedRE.MatchString(trimmed):
			errors = append(errors, line)
			inCargoError = true
		case npmWarnDeprecatedRE.MatchString(trimmed):
			deprecations = append(deprecations, line)
		case npmWarnRE.MatchString(trimmed), yarnWarnRE.MatchString(trimmed), warningLineRE.MatchString(trimmed), strings.HasPrefix(trimmed, "warning -->"), bracketWarningRE.MatchString(trimmed):
			warnings = append(warnings, line)
			inCargoError = strings.HasPrefix(trimmed, "warning -->")
		case compilingRE.MatchString(trimmed):
			compilingCount++
		case downloadingRE.MatchString(trimmed):
			downloadingCount++
		case buildSummaryRE.MatchString(trimmed):
			if summary == "" {
				summary = line
			} else {
				summary += "\n" + line
			}
		}
	}
	var out []string
	keepDep := 3
	if len(deprecations) < keepDep {
		keepDep = len(deprecations)
	}
	out = append(out, deprecations[:keepDep]...)
	if len(deprecations) > keepDep {
		out = append(out, "... +"+stringInt(len(deprecations)-keepDep)+" more deprecated packages")
	}
	if compilingCount > 0 {
		out = append(out, "Compiled "+stringInt(compilingCount)+" packages")
	}
	if downloadingCount > 0 {
		out = append(out, "Downloaded "+stringInt(downloadingCount)+" packages")
	}
	out = append(out, errors...)
	keepWarnings := 5
	if len(warnings) < keepWarnings {
		keepWarnings = len(warnings)
	}
	out = append(out, warnings[:keepWarnings]...)
	if len(warnings) > keepWarnings {
		out = append(out, "... +"+stringInt(len(warnings)-keepWarnings)+" more warnings")
	}
	if summary != "" {
		out = append(out, strings.Split(summary, "\n")...)
	}
	if len(out) == 0 {
		return input
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func dedupLog(text string) string {
	const maxLine = 2000
	lines := strings.Split(text, "\n")
	seen := map[string]int{}
	var out []string
	omitted := 0
	for _, line := range lines {
		key := line
		if len(key) > maxLine {
			key = key[:maxLine]
		}
		seen[key]++
		if seen[key] <= 3 {
			out = append(out, line)
		} else {
			omitted++
		}
	}
	if omitted > 0 {
		out = append(out, "... "+stringInt(omitted)+" duplicate lines omitted")
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func smartTruncate(text string) string {
	lines := strings.Split(text, "\n")
	const head = 120
	const tail = 60
	if len(lines) <= head+tail {
		return text
	}
	out := append([]string{}, lines[:head]...)
	out = append(out, "... "+stringInt(len(lines)-head-tail)+" lines omitted ...")
	out = append(out, lines[len(lines)-tail:]...)
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

func readNumbered(text string) string {
	lines := strings.Split(text, "\n")
	return smartTruncate(strings.Join(lines, "\n"))
}

func compactTree(text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	for _, line := range lines {
		if strings.Contains(line, "director") && strings.Contains(line, "file") {
			continue
		}
		if strings.TrimSpace(line) == "" && len(out) == 0 {
			continue
		}
		out = append(out, line)
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	const maxLines = 200
	if len(out) > maxLines {
		return strings.Join(out[:maxLines], "\n") + "\n... +" + stringInt(len(out)-maxLines) + " more lines"
	}
	return strings.Join(out, "\n")
}

type lsEntry struct {
	fileType byte
	size     int64
	name     string
}

func compactLS(text string) string {
	var entries []lsEntry
	for _, line := range strings.Split(text, "\n") {
		if entry, ok := parseLSLine(line); ok {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return text
	}
	dirs, files, totalSize := 0, 0, int64(0)
	exts := map[string]int{}
	for _, entry := range entries {
		if entry.fileType == 'd' {
			dirs++
			continue
		}
		files++
		totalSize += entry.size
		if idx := strings.LastIndex(entry.name, "."); idx >= 0 && idx < len(entry.name)-1 {
			exts[strings.ToLower(entry.name[idx:])]++
		}
	}
	out := []string{"ls: " + stringInt(files) + " files, " + stringInt(dirs) + " dirs, " + humanSize(totalSize)}
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range exts {
		pairs = append(pairs, kv{k: k, v: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v == pairs[j].v {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v > pairs[j].v
	})
	for i, p := range pairs {
		if i >= 5 {
			break
		}
		out = append(out, p.k+": "+stringInt(p.v))
	}
	return strings.Join(out, "\n")
}

func parseLSLine(line string) (lsEntry, bool) {
	if len(line) < 10 || !lsPermRE.MatchString(line[:10]) {
		return lsEntry{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return lsEntry{}, false
	}
	size, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return lsEntry{}, false
	}
	return lsEntry{fileType: line[0], size: size, name: strings.Join(fields[8:], " ")}, true
}

func compactSearchList(text string) string {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || !searchListHeaderRE.MatchString(lines[0]) {
		return text
	}
	var paths []string
	for _, raw := range lines[1:] {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "- ") {
			paths = append(paths, strings.TrimSpace(strings.TrimPrefix(t, "- ")))
		}
	}
	if len(paths) == 0 {
		return text
	}
	return lines[0] + "\n" + compactPathBasenames(paths, 10, 20)
}

var (
	grepLineRE          = regexp.MustCompile(`^.+:\d+:.+`)
	porcelainRE         = regexp.MustCompile(`^[ MADRCU?!][ MADRCU?!] \S`)
	lsPermRE            = regexp.MustCompile(`^[-dlbcps][rwx-]{9}$`)
	readNumberedLineRE  = regexp.MustCompile(`^\s*\d+\|`)
	searchListHeaderRE  = regexp.MustCompile(`^Result of search in '.+' \(total \d+ files\):`)
	cargoErrContRE      = regexp.MustCompile(`^\s*(-->|\||\d+\s*\||=)`)
	buildOutputRE       = regexp.MustCompile(`(?i)^(npm (warn|error|ERR!)|yarn (warn|error)|\s*Compiling\s+\S+|\s*Downloading\s+\S+|added \d+ package|\[ERROR\]|BUILD (SUCCESS|FAILED)|\s*Finished\s+|Successfully (installed|built)|ERROR:)`)
	npmErrorRE          = regexp.MustCompile(`(?i)^npm (ERR!|error)`)
	yarnErrorRE         = regexp.MustCompile(`(?i)^yarn error`)
	npmWarnDeprecatedRE = regexp.MustCompile(`(?i)^npm warn deprecated`)
	npmWarnRE           = regexp.MustCompile(`(?i)^npm warn`)
	yarnWarnRE          = regexp.MustCompile(`(?i)^yarn warn`)
	errorLineRE         = regexp.MustCompile(`(?i)^error(\[|:)`)
	warningLineRE       = regexp.MustCompile(`(?i)^warning(\[|:)`)
	bracketWarningRE    = regexp.MustCompile(`(?i)^\[WARNING\]`)
	buildFailedRE       = regexp.MustCompile(`(?i)^\[ERROR\]|^BUILD FAILED`)
	compilingRE         = regexp.MustCompile(`(?i)^\s*Compiling\s+\S+`)
	downloadingRE       = regexp.MustCompile(`(?i)^\s*Downloading\s+\S+|^Fetching\s+`)
	buildSummaryRE      = regexp.MustCompile(`(?i)^(added|removed|changed|audited|installed)\s+\d+\s+package|^\s*Finished\s+|^BUILD SUCCESS|^\d+\s+(vulnerabilities|packages?|warnings?|errors?)|^Successfully (installed|built)|^To address .* issues|^Run ` + "`" + `npm (audit|fund)` + "`" + `|packages are looking for funding`)
	envAssignRE         = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

func looksLikeGrep(head string) bool {
	lines := nonEmptyLines(head)
	limit := 5
	if len(lines) < limit {
		limit = len(lines)
	}
	for _, line := range lines[:limit] {
		if grepLineRE.MatchString(line) {
			return true
		}
	}
	return false
}

func looksLikePathList(head string) bool {
	lines := nonEmptyLines(head)
	if len(lines) < 3 {
		return false
	}
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.Contains(t, ":") {
			return false
		}
		if !(strings.HasPrefix(t, ".") || strings.HasPrefix(t, "/") || strings.Contains(t, "/")) {
			return false
		}
	}
	return true
}

func looksLikePorcelain(head string) bool {
	lines := nonEmptyLines(head)
	if len(lines) < 3 {
		return false
	}
	hits := 0
	for _, line := range lines {
		if porcelainRE.MatchString(line) {
			hits++
		}
	}
	return hits*10 >= len(lines)*6
}

func looksLikeBuildOutput(head string) bool {
	for _, line := range strings.Split(head, "\n") {
		if buildOutputRE.MatchString(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

func looksLikeLS(head string) bool {
	if regexp.MustCompile(`(?m)^total \d+$`).MatchString(head) {
		return true
	}
	count := 0
	for _, line := range strings.Split(head, "\n") {
		if len(line) >= 10 && lsPermRE.MatchString(line[:10]) {
			count++
		}
	}
	return count >= 3
}

func isLineNumbered(lines []string) bool {
	hits, nonEmpty := 0, 0
	limit := 100
	if len(lines) < limit {
		limit = len(lines)
	}
	for _, line := range lines[:limit] {
		if line == "" {
			continue
		}
		nonEmpty++
		if readNumberedLineRE.MatchString(line) {
			hits++
		}
	}
	return nonEmpty >= 5 && hits*10 >= nonEmpty*7
}

func nonEmptyLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func humanSize(bytes int64) string {
	switch {
	case bytes >= 1_048_576:
		return strconv.FormatFloat(float64(bytes)/1_048_576, 'f', 1, 64) + "M"
	case bytes >= 1024:
		return strconv.FormatFloat(float64(bytes)/1024, 'f', 1, 64) + "K"
	default:
		return stringInt(int(bytes)) + "B"
	}
}

func leftPad(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return strings.Repeat(" ", width-len(value)) + value
}

func stringInt(n int) string {
	return strconv.Itoa(n)
}

func toolCommands(payload any) map[string]string {
	cmds := map[string]string{}
	collectToolCommands(payload, cmds)
	if len(cmds) == 0 {
		return nil
	}
	return cmds
}

func collectToolCommands(v any, cmds map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		switch typeName, _ := val["type"].(string); typeName {
		case "function_call":
			id, _ := val["call_id"].(string)
			if strings.TrimSpace(id) == "" {
				id, _ = val["id"].(string)
			}
			if cmd := commandFromToolCall(val); id != "" && cmd != "" {
				cmds[id] = cmd
			}
		case "tool_use":
			id, _ := val["id"].(string)
			if cmd := commandFromToolCall(val); id != "" && cmd != "" {
				cmds[id] = cmd
			}
		}
		if calls, ok := val["tool_calls"].([]any); ok {
			for _, call := range calls {
				if m, ok := call.(map[string]any); ok {
					id, _ := m["id"].(string)
					if cmd := commandFromToolCall(m); id != "" && cmd != "" {
						cmds[id] = cmd
					}
				}
			}
		}
		for _, child := range val {
			collectToolCommands(child, cmds)
		}
	case []any:
		for _, child := range val {
			collectToolCommands(child, cmds)
		}
	}
}

func commandFromToolCall(m map[string]any) string {
	name, _ := m["name"].(string)
	input := m["input"]
	if fn, ok := m["function"].(map[string]any); ok {
		if name == "" {
			name, _ = fn["name"].(string)
		}
		input = fn["arguments"]
	}
	if !isShellToolName(name) {
		return ""
	}
	switch v := input.(type) {
	case map[string]any:
		for _, key := range []string{"cmd", "command", "script"} {
			if s, ok := v[key].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	case string:
		var parsed map[string]any
		if json.Unmarshal([]byte(v), &parsed) == nil {
			return commandFromToolCall(map[string]any{"name": name, "input": parsed})
		}
	}
	return ""
}

func isShellToolName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n == "shell" || n == "bash" || n == "terminal" || n == "exec" ||
		n == "exec_command" || strings.Contains(n, "shell") || strings.Contains(n, "terminal")
}

func filterForCommand(command string) string {
	words := shellWords(command)
	for len(words) > 0 && envAssignRE.MatchString(words[0]) {
		words = words[1:]
	}
	if len(words) == 0 {
		return ""
	}
	cmd := strings.TrimSuffix(words[0], ",")
	base := cmd
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	switch base {
	case "git":
		if len(words) > 1 {
			switch words[1] {
			case "diff", "show":
				return "git-diff"
			case "status":
				return "git-status"
			}
		}
	case "rg", "grep", "ag":
		return "grep"
	case "find", "fd":
		return "find"
	case "ls", "ll":
		return "ls"
	case "tree":
		return "tree"
	case "npm", "yarn", "pnpm", "cargo", "go", "mvn", "gradle", "make", "pip", "uv":
		return "build-output"
	case "sed", "awk", "nl", "cat":
		return "read-numbered"
	}
	return ""
}

func commandIsGit(command string) bool {
	words := shellWords(command)
	for len(words) > 0 && envAssignRE.MatchString(words[0]) {
		words = words[1:]
	}
	return len(words) > 0 && strings.TrimSuffix(words[0], ",") == "git"
}

func shellWords(command string) []string {
	var words []string
	var b strings.Builder
	inSingle, inDouble, escaped := false, false, false
	for _, r := range command {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case (r == ' ' || r == '\t' || r == '\n') && !inSingle && !inDouble:
			if b.Len() > 0 {
				words = append(words, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		words = append(words, b.String())
	}
	return words
}
