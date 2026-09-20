package pkginfo

import (
	"sort"
	"strings"

	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/type/stringsutil"
)

type PkgInfo struct {
	Name    string
	Version string
}

func (pkg PkgInfo) String() string {
	name := strings.TrimSpace(pkg.Name)
	ver := strings.TrimSpace(pkg.Version)
	if name == "" {
		return ""
	} else if ver == "" {
		return name
	} else {
		return name + "@" + ver
	}
}

type PkgInfos []PkgInfo

func (pkgs PkgInfos) Sort() {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Version < pkgs[j].Version
		}
		iName := strings.TrimPrefix(pkgs[i].Name, "@")
		jName := strings.TrimPrefix(pkgs[j].Name, "@")
		return iName < jName
	})
}

func (pkgs PkgInfos) Strings() []string {
	var out []string
	for _, pkg := range pkgs {
		if s := pkg.String(); s != "" {
			out = append(out, s)
		}
	}
	return stringsutil.SliceCondenseSpace(out, true, true)
}

/*
func (pkgs PkgInfos) Strings() []string {
	var out []string
	for _, pkg := range pkgs {

	}
	return out
}
*/

func NPMQixHackEvenPkgInfosAll() PkgInfos {
	pkgs1 := NPMQixHackEvenPkgInfos()
	pkgs2 := NPMQixHackEvent2()
	pkgs := PkgInfos{}
	if len(pkgs1) > 0 {
		pkgs = append(pkgs, pkgs1...)
	}
	if len(pkgs2) > 0 {
		pkgs = append(pkgs, pkgs2...)
	}
	return pkgs
}

func NPMQixHackEvenPkgInfos() PkgInfos {
	var out PkgInfos
	raw := NPMQixHackEventRaw()
	raws := strings.Split(raw, "\n")
	for _, r := range raws {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		parts := strings.Split(r, "@")
		var name string
		var ver string
		if len(parts) < 2 {
			fmtutil.MustPrintJSON(parts)
			panic("wrong_len")
		} else if len(parts) == 2 {
			name = parts[0]
			ver = parts[1]
		} else {
			name = strings.Join(parts[:len(parts)-1], "@")
			ver = parts[len(parts)-1]
		}
		out = append(out, PkgInfo{
			Name:    name,
			Version: ver,
		})
	}
	out.Sort()
	return out
}

func NPMQixHackEventRaw() string {
	return `ansi-regex@6.2.1
ansi-styles@6.2.2
backslash@0.2.1
chalk-template@1.1.1
chalk@5.6.1
color-convert@3.1.1
color-name@2.0.1
color-string@2.1.1
color@5.0.1
@coveops/abi@2.0.1
debug@4.4.2
@duckdb/duckdb-wasm@1.29.2
@duckdb/node-api@1.3.3
@duckdb/node-bindings@1.3.3
duckdb@1.3.3
has-ansi@6.0.1
is-arrayish@0.3.3
prebid@10.9.1
prebid@10.9.2
simple-swizzle@0.2.3
slice-ansi@7.1.1
strip-ansi@7.1.1
supports-color@10.2.1
supports-hyperlinks@4.1.1
wrap-ansi@9.0.1`
}

func NPMQixHackEvent2() PkgInfos {
	var out PkgInfos
	raw := NPMQixHackEventRaw2()
	raws := strings.Split(raw, "\n")
	for _, r := range raws {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		parts := strings.Split(r, " : ")
		if len(parts) != 2 {
			panic("wrong_len")
		}
		out = append(out, PkgInfo{
			Name:    strings.TrimSpace(parts[0]),
			Version: strings.TrimSpace(parts[1]),
		})
	}
	return out
}

func NPMQixHackEventRaw2() string {
	return `@coveops/abi : 2.0.1 
@duckdb/node-api : 1.3.3 
@duckdb/node-bindings : 1.3.3 
ansi-regex : 6.2.1 
ansi-styles : 6.2.2 
backslash : 0.2.1 
chalk : 5.6.1 
chalk-template : 1.1.1 
color : 5.0.1 
color-convert : 3.1.1 
color-name : 2.0.1 
color-string : 2.1.1 
debug : 4.4.2 
duckdb : 1.3.3 
error-ex : 1.3.3 
has-ansi : 6.0.1 
is-arrayish : 0.3.3 
prebid : 10.9.2 
prebid-universal-creative : 1.17.3 
prebid.js : 10.9.2 
proto-tinker-wc : 0.1.87 
simple-swizzle : 0.2.3 
slice-ansi : 7.1.1 
strip-ansi : 7.1.1 
supports-color : 10.2.1 
supports-hyperlinks : 4.1.1 
wrap-ansi : 9.0.1`
}

/*

@coveops/abi : 2.0.1
@duckdb/node-api : 1.3.3
@duckdb/node-bindings : 1.3.3
ansi-regex : 6.2.1
ansi-styles : 6.2.2
backslash : 0.2.1
chalk : 5.6.1
chalk-template : 1.1.1
color : 5.0.1
color-convert : 3.1.1
color-name : 2.0.1
color-string : 2.1.1
debug : 4.4.2
duckdb - 1.3.3
error-ex : 1.3.3
has-ansi : 6.0.1
is-arrayish : 0.3.3
prebid : 10.9.2
prebid-universal-creative : 1.17.3
prebid.js : 10.9.2
proto-tinker-wc : 0.1.87
simple-swizzle : 0.2.3
slice-ansi : 7.1.1
strip-ansi : 7.1.1
supports-color : 10.2.1
supports-hyperlinks : 4.1.1
wrap-ansi : 9.0.1
*/
