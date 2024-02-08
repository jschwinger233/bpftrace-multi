package target

import (
	"fmt"
	"strings"
)

type Target interface {
	ID() string
	Blocks() ([]Block, error)
	Validate() error
}

type Block interface {
	ID() string
	ProbeTargets() []string
	VarReplaceFunc() func(string) string
	Begins() []string
}

func New(target string, paramMap bool) (targetObj Target, err error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid target: %s", target)
	}
	switch parts[0] {
	case "has_param":
		targetObj = newTargetHasParam(parts[1], paramMap)
	case "has_retval":
		targetObj = newTargetHasRetval(parts[1], paramMap)
	case "from_file":
		targetObj = newTargetFromFile(parts[1], paramMap)
	default:
		return nil, fmt.Errorf("unknown target: %s", parts[0])
	}
	return targetObj, targetObj.Validate()
}
