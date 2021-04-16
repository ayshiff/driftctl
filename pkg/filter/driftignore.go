package filter

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cloudskiff/driftctl/pkg/analyser"
	"github.com/cloudskiff/driftctl/pkg/resource"
	"github.com/sirupsen/logrus"
)

const DriftIgnoreFilename = ".driftignore"

type DriftIgnore struct {
	resExclusionList         map[string]struct{} // map[type.id] exists to ignore
	resExclusionWildcardList map[string]struct{} // map[type.id] exists with wildcard to ignore
	driftExclusionList       map[string][]string // map[type.id] contains path for drift to ignore
}

type AnalysisListOptions struct {
	IncludeUnmanaged bool
	IncludeDeleted   bool
	IncludeDrifted   bool
}

func NewDriftIgnore() *DriftIgnore {
	d := DriftIgnore{
		resExclusionList:         map[string]struct{}{},
		resExclusionWildcardList: map[string]struct{}{},
		driftExclusionList:       map[string][]string{},
	}
	err := d.readIgnoreFile()
	if err != nil {
		logrus.Debug(err)
	}
	return &d
}

func (r *DriftIgnore) readIgnoreFile() error {
	file, err := os.Open(DriftIgnoreFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			logrus.WithFields(logrus.Fields{
				"line": line,
			}).Debug("Skipped comment or empty line")
			continue
		}
		typeVal := readDriftIgnoreLine(line)
		nbArgs := len(typeVal)
		if nbArgs < 2 {
			logrus.WithFields(logrus.Fields{
				"line":    strconv.Itoa(lineNumber),
				"content": line,
			}).Warnf("unable to parse line, invalid length, got %d expected >= 2", nbArgs)
			continue
		}
		res := strings.Join(typeVal[0:2], ".")
		if nbArgs == 2 { // We want to ignore a resource (type.id)
			logrus.WithFields(logrus.Fields{
				"type": typeVal[0],
				"id":   typeVal[1],
			}).Debug("Found ignore resource rule in .driftignore")
			resExclusionTypeList := r.resExclusionList
			if strings.Contains(res, "*") {
				resExclusionTypeList = r.resExclusionWildcardList
			}
			resExclusionTypeList[res] = struct{}{}
			continue
		}
		// Here we want to ignore a drift (type.id.path.to.field)
		ignoreSublist, exists := r.driftExclusionList[res]
		if !exists {
			ignoreSublist = make([]string, 0, 1)
		}
		path := strings.Join(typeVal[2:], ".")

		logrus.WithFields(logrus.Fields{
			"type": typeVal[0],
			"id":   typeVal[1],
			"path": path,
		}).Debug("Found ignore resource field rule in .driftignore")

		ignoreSublist = append(ignoreSublist, path)
		r.driftExclusionList[res] = ignoreSublist
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (r *DriftIgnore) IsResourceIgnored(res resource.Resource) bool {
	strRes := fmt.Sprintf("%s.%s", res.TerraformType(), res.TerraformId())

	if _, isExclusionRule := r.resExclusionList[strRes]; isExclusionRule {
		return true
	}
	for resExclusion := range r.resExclusionWildcardList {
		if wildcardMatchChecker(strRes, resExclusion) {
			return true
		}
	}
	return false
}

func (r *DriftIgnore) IsFieldIgnored(res resource.Resource, path []string) bool {
	exclusionRules, isExclusionRule := r.driftExclusionList[fmt.Sprintf("%s.%s", res.TerraformType(), res.TerraformId())]
	exclusionWildcardRules, isExclusionWildcardRule := r.driftExclusionList[fmt.Sprintf("%s.*", res.TerraformType())]

	if !isExclusionRule && !isExclusionWildcardRule {
		return false
	}

	if !isExclusionRule {
		exclusionRules = exclusionWildcardRules
	}

	if r.isExcluded(exclusionRules, path) {
		return true
	}

	return false
}

func (r *DriftIgnore) isExcluded(rules []string, changePath []string) bool {
RuleCheck:
	for _, rule := range rules {
		path := readDriftIgnoreLine(rule)
		if len(path) > len(changePath) {
			continue // path size does not match
		}

		for i := range path {
			if !strings.EqualFold(path[i], changePath[i]) && path[i] != "*" {
				continue RuleCheck // found a diff in path that was not a wildcard
			}
		}
		return true
	}
	return false
}

func AnalysisToList(analysis *analyser.Analysis, opts AnalysisListOptions) (int, string) {
	var list []string

	n := 0

	addResources := func(res ...resource.Resource) {
		for _, r := range res {
			list = append(list, fmt.Sprintf("%s.%s", escapeKey(r.TerraformType()), escapeKey(r.TerraformId())))
		}
	}

	addDifferences := func(diff ...analyser.Difference) {
		for _, d := range diff {
			addResources(d.Res)
		}
	}

	if opts.IncludeUnmanaged && analysis.Summary().TotalUnmanaged > 0 {
		list = append(list, "# Resources not covered by IaC")
		addResources(analysis.Unmanaged()...)
		n += analysis.Summary().TotalUnmanaged
	}

	if opts.IncludeDeleted && analysis.Summary().TotalDeleted > 0 {
		list = append(list, "# Missing resources")
		addResources(analysis.Deleted()...)
		n += analysis.Summary().TotalUnmanaged
	}

	if opts.IncludeDrifted && analysis.Summary().TotalDrifted > 0 {
		list = append(list, "# Changed resources")
		addDifferences(analysis.Differences()...)
		n += analysis.Summary().TotalUnmanaged
	}

	return n, strings.Join(list, "\n")
}

func escapeKey(line string) string {
	line = strings.ReplaceAll(line, "\\", `\\`)
	line = strings.ReplaceAll(line, ".", "\\.")

	return line
}

//Check two strings recursively, pattern can contain wildcard
func wildcardMatchChecker(str, pattern string) bool {
	if str == "" && pattern == "" {
		return true
	}
	if strings.HasPrefix(pattern, "*") {
		if str != "" {
			return wildcardMatchChecker(str[1:], pattern) || wildcardMatchChecker(str, pattern[1:])
		}
		return wildcardMatchChecker(str, pattern[1:])
	}
	if str != "" && pattern != "" && str[0] == pattern[0] {
		return wildcardMatchChecker(str[1:], pattern[1:])
	}
	return false
}

/**
 * Read a line of ignore
 * Handle multiple asterisks escaping
 * Handle split on dots and escaping
 */
func readDriftIgnoreLine(line string) []string {
	for strings.Contains(line, "**") {
		line = strings.ReplaceAll(line, "**", "*")
	}

	var splitted []string
	lastWordEnd := 0
	for i := range line {
		if line[i] == '.' && ((i >= 1 && line[i-1] != '\\') || (i >= 2 && line[i-1] == '\\' && line[i-2] == '\\')) {
			splitted = append(splitted, unescapeDriftIgnoreLine(line[lastWordEnd:i]))
			lastWordEnd = i + 1
			continue
		}
		if i == len(line)-1 {
			splitted = append(splitted, unescapeDriftIgnoreLine(line[lastWordEnd:]))
		}
	}
	return splitted
}

func unescapeDriftIgnoreLine(line string) string {
	var res string
	lastEscapeEnd := 0
	for i := range line {
		if line[i] == '\\' {
			if i+1 < len(line) && line[i+1] == '\\' {
				continue
			}
			if i > 1 && line[i-1] == '\\' {
				res += line[lastEscapeEnd:i]
				lastEscapeEnd = i + 1
				continue
			}
			res += line[lastEscapeEnd:i]
			lastEscapeEnd = i + 1
			continue
		}
		if i == len(line)-1 {
			res += line[lastEscapeEnd:]
		}
	}

	return res
}
