package features

type VmessOptions struct {
	UseIPv6        bool   `json:"useIPv6"`
	Loglevel       string `json:"logLevel"`
	RouteMode      int    `json:"routeMode"` // for SSRRAY
	EnableSniffing bool   `json:"enableSniffing"`
	DNS            string `json:"dns"` // DNS Config
	AllowInsecure  bool   `json:"allowInsecure"`
	Mux            int    `json:"mux"`
	LocalPort      int    `json:"localPort"`
}
