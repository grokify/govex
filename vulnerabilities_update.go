package govex

type VulnerabilitiesUpdateOpts struct {
	Modules    map[string]string
	Severities map[string]string
}

func (vs *Vulnerabilities) Update(opts VulnerabilitiesUpdateOpts) {
	vs.UpdateModules(opts.Modules)
	vs.UpdateSeverities(opts.Severities)
}

func (vs *Vulnerabilities) UpdateModules(old2new map[string]string) {
	if len(old2new) == 0 {
		return
	}
	for i, vn := range *vs {
		if new, ok := old2new[vn.Module]; ok {
			vn.Module = new
			(*vs)[i] = vn
		}
	}
}

func (vs *Vulnerabilities) UpdateSeverities(old2new map[string]string) {
	if len(old2new) == 0 {
		return
	}
	for i, vn := range *vs {
		if new, ok := old2new[vn.Severity]; ok {
			vn.Severity = new
			(*vs)[i] = vn
		}
	}
}
