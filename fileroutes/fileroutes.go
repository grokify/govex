package fileroutes

type FileRouteMap struct {
	Paths map[string]URLPath `json:"paths"` // key = URL path
}

type URLPath struct {
	Path      string                 `json:"path"` // same as key in FileRouteMap.Paths
	Filepaths []string               `json:"filepaths"`
	Methods   map[string]*MethodItem `json:"methods"`
}

type MethodItem struct {
	HandlerName string `json:"handlerName,omitempty"`
	Line        int    `json:"line,omitempty"`
}
