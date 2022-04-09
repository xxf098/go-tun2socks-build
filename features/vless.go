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

func NewVless(Add string, Port int, Password string, TLS string, HeaderType string, Security string, ID string, Net string, opt []byte) *Vless {
	options := NewVmessOptions(opt)
	return &Vless{
		TLS:          TLS,
		Add:          Add,
		Port:         Port,
		Net:          Net,
		ID:           ID,
		Type:         HeaderType,
		Security:     Security,
		Protocol:     "vless",
		VmessOptions: options,
	}
}
