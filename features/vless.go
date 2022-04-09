package features

type Vless struct {
	TLS      string
	Add      string
	Port     int
	Net      string
	ID       string
	Type     string // headerType
	Security string // vnext.Security
	Protocol string
	VmessOptions
}
