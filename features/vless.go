package features

type Vless struct {
	TLS        string
	Add        string
	Port       int
	Net        string
	ID         string
	Type       string // headerType
	Security   string // VlessUser.Security
	Encryption string // VlessUser.encryption
	Flow       string // VlessUser.flow
	Protocol   string
	Path       string // ws path
	Host       string // ws host / http host
	SNI        string // tls sni
	VmessOptions
}

func NewVless(Add string, Port int, ID string, TLS string, HeaderType string, Encryption string, Net string, Flow string, Security string, Path string, Host string, SNI string, opt []byte) *Vless {
	options := NewVmessOptions(opt)
	return &Vless{
		TLS:          TLS,
		Add:          Add,
		Port:         Port,
		Net:          Net,
		ID:           ID,
		Type:         HeaderType,
		Encryption:   Encryption,
		Flow:         Flow,
		Security:     Security,
		Path:         Path,
		Host:         Host,
		SNI:          SNI,
		Protocol:     "vless",
		VmessOptions: options,
	}
}
