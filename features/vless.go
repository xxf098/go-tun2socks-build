package features

type Vless struct {
	TLS        string
	Add        string
	Port       int
	Net        string
	ID         string
	Type       string // headerType
	Encryption string // VlessUser.encryption
	Flow       string // VlessUser.flow
	Protocol   string
	VmessOptions
}

func NewVless(Add string, Port int, ID string, TLS string, HeaderType string, Encryption string, Net string, Flow string, opt []byte) *Vless {
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
		Protocol:     "vless",
		VmessOptions: options,
	}
}
