package features

type Shadowsocks struct {
	Add      string
	Port     int
	Password string
	Method   string
	VmessOptions
}

func NewShadowsocks(Add string, Port int, Password string, Method string, opt []byte) *Shadowsocks {
	options := NewVmessOptions(opt)
	return &Shadowsocks{
		Add:          Add,
		Port:         Port,
		Password:     Password,
		Method:       Method,
		VmessOptions: options,
	}
}
