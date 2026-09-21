# FileRoutes Package

The `fileroutes` package provides a small, JSON-serializable model that maps URL paths to the source files and HTTP methods/handlers that implement them. It is useful for building an API route inventory — for example, correlating findings with the routes and handlers they affect.

## Installation

```go
import "github.com/grokify/govex/fileroutes"
```

## Types

The package is a pure data model with three types.

| Type | Description |
|------|-------------|
| `FileRouteMap` | Top-level container keyed by URL path |
| `URLPath` | A single URL path, its source files, and its methods |
| `MethodItem` | One HTTP method's handler name and source line |

### FileRouteMap

`FileRouteMap` holds all routes keyed by URL path:

```go
type FileRouteMap struct {
    Paths map[string]URLPath `json:"paths"` // key = URL path
}
```

### URLPath

`URLPath` describes a single route. `Path` mirrors the map key, `Filepaths` lists the source files that implement the route, and `Methods` maps each HTTP method to its handler:

```go
type URLPath struct {
    Path      string                 `json:"path"`
    Filepaths []string               `json:"filepaths"`
    Methods   map[string]*MethodItem `json:"methods"`
}
```

### MethodItem

`MethodItem` records the handler that serves a given method and the line where it is defined. Both fields are optional (`omitempty`):

```go
type MethodItem struct {
    HandlerName string `json:"handlerName,omitempty"`
    Line        int    `json:"line,omitempty"`
}
```

## JSON Shape

```json
{
  "paths": {
    "/api/v1/users": {
      "path": "/api/v1/users",
      "filepaths": ["api/users.go"],
      "methods": {
        "GET": {
          "handlerName": "ListUsers",
          "line": 42
        },
        "POST": {
          "handlerName": "CreateUser",
          "line": 78
        }
      }
    }
  }
}
```

## Example

```go
package main

import (
    "encoding/json"
    "fmt"

    "github.com/grokify/govex/fileroutes"
)

func main() {
    m := fileroutes.FileRouteMap{
        Paths: map[string]fileroutes.URLPath{
            "/api/v1/users": {
                Path:      "/api/v1/users",
                Filepaths: []string{"api/users.go"},
                Methods: map[string]*fileroutes.MethodItem{
                    "GET":  {HandlerName: "ListUsers", Line: 42},
                    "POST": {HandlerName: "CreateUser", Line: 78},
                },
            },
        },
    }

    b, _ := json.MarshalIndent(m, "", "  ")
    fmt.Println(string(b))
}
```

## Related

- [Core Package](core.md) - Vulnerability types that findings can be correlated against
