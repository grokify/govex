package govex

type Library struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Version      string `json:"version"`
	VersionFixed string `json:"versionFixed"`
}
