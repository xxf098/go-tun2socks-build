package features

type Trojan struct {
	Add            string
	Port           int
	Password       string
	SNI            string
	SkipCertVerify bool
	VmessOptions
}

func NewTrojan(Add string, Port int, Password string, SNI string, SkipCertVerify bool, opt []byte) *Trojan {
	options := NewVmessOptions(opt)
	return &Trojan{
		Add:            Add,
		Port:           Port,
		Password:       Password,
		SNI:            SNI,
		SkipCertVerify: SkipCertVerify,
		VmessOptions:   options,
	}
}
