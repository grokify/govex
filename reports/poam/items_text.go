package poam

import (
	"errors"
	"fmt"
	"strings"
)

type POAMItemUpgradeRemedationInfo struct {
	VulnerabilityID string
	SLADays         int64
	Packages        POAMItemUpgradeRemedationPackages
}

const POAMItemRemediationTemplate = `%s identifies a vulnerability that vulnerability affects the following packages used in our system: %s. Each affected component will be upgraded to the secure version that addresses the CVE: %s. Changes will go through our established change management and security validation processes. Completion of all remediation activities and confirmation via follow-up scans is targeted within %d calendar days of identification.`

func (info POAMItemUpgradeRemedationInfo) String() (string, error) {
	vulnID := info.VulnerabilityID
	if vulnID == "" {
		return "", errors.New("vulnID cannot be empty")
	}
	if info.SLADays == 0 {
		return "", errors.New("sla days cannot be zero")
	}
	if len(info.Packages) == 0 {
		return "", errors.New("packages cannot be empty")
	}
	curPkgs, err := info.Packages.NameVersionPackageManagers(false, true)
	if err != nil {
		return "", err
	}
	fixPkgs, err := info.Packages.NameVersionPackageManagers(true, false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(POAMItemRemediationTemplate, vulnID, curPkgs, fixPkgs, info.SLADays), nil
}

type POAMItemUpgradeRemedationPackages []POAMItemUpgradeRemedationPackage

func (pkgs POAMItemUpgradeRemedationPackages) NameVersionPackageManagers(wantFixVersion, addPkgMgr bool) (string, error) {
	var names []string
	for _, pkg := range pkgs {
		if name, err := pkg.NameVersionPackageManager(wantFixVersion, addPkgMgr); err != nil {
			return "", err
		} else {
			names = append(names, name)
		}
	}
	return strings.Join(names, "; "), nil
}

type POAMItemUpgradeRemedationPackage struct {
	Name           string
	CurVersion     string
	FixVersion     string
	PackageManager string
}

func (pkg POAMItemUpgradeRemedationPackage) NameVersionPackageManager(wantFixVersion, addPkgMgr bool) (string, error) {
	var out []string
	if name := strings.TrimSpace(pkg.Name); name == "" {
		return "", errors.New("package has no name")
	} else {
		out = append(out, name)
	}
	if wantFixVersion {
		if fixver := strings.TrimSpace(pkg.FixVersion); fixver != "" {
			out = append(out, fixver)
		}
	} else {
		if curver := strings.TrimSpace(pkg.CurVersion); curver != "" {
			out = append(out, curver)
		}
	}
	if addPkgMgr {
		if pkgmgr := strings.TrimSpace(pkg.PackageManager); pkgmgr != "" {
			out = append(out, "("+pkgmgr+")")
		}
	}
	return strings.Join(out, " "), nil
}
