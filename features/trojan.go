package features

type Trojan struct {
	Add            string
	Port           int
	Password       string
	SNI            string
	SkipCertVerify bool
	Net            string
	Path           string // ws path
	Host           string // ws host / http host
	VmessOptions
}

func NewTrojan(
	Add string,
	Port int,
	Password string,
	SNI string,
	SkipCertVerify bool,
	Net string,
	Path string,
	Host string,
	opt []byte) *Trojan {
	options := NewVmessOptions(opt)
	return &Trojan{
		Add:            Add,
		Port:           Port,
		Password:       Password,
		SNI:            SNI,
		SkipCertVerify: SkipCertVerify,
		Net:            Net,
		Path:           Path,
		Host:           Host,
		VmessOptions:   options,
	}
}
