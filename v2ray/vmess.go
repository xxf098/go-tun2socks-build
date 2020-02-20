package v2ray

type VmessConfig struct {
	DNS       DNS         `json:"dns"`
	Inbounds  []Inbounds  `json:"inbounds"`
	Log       Log         `json:"log"`
	Outbounds []Outbounds `json:"outbounds"`
	Routing   Routing     `json:"routing"`
}

type Hosts map[string]string

type DNS struct {
	Hosts   Hosts    `json:"hosts"`
	Servers []string `json:"servers"`
}
type InboundsSettings struct {
	Auth string `json:"auth"`
	IP   string `json:"ip"`
	UDP  bool   `json:"udp"`
}
type Inbounds struct {
	Listen           string            `json:"listen"`
	Port             int               `json:"port"`
	Protocol         string            `json:"protocol"`
	InboundsSettings *InboundsSettings `json:"settings,omitempty"`
	Tag              string            `json:"tag"`
}
type Log struct {
	Access   string `json:"access"`
	Error    string `json:"error"`
	Loglevel string `json:"loglevel"`
}
type Mux struct {
	Enabled bool `json:"enabled"`
}
type Users struct {
	AlterID  int    `json:"alterId"`
	Email    string `json:"email"`
	ID       string `json:"id"`
	Security string `json:"security"`
}
type Vnext struct {
	Address string  `json:"address"`
	Port    int     `json:"port"`
	Users   []Users `json:"users"`
}
type OutboundsSettings struct {
	Vnext          []Vnext `json:"vnext,omitempty"`
	DomainStrategy string  `json:"domainStrategy,omitempty"`
}
type Headers struct {
	Host string `json:"Host"`
}
type Wssettings struct {
	ConnectionReuse bool    `json:"connectionReuse"`
	Headers         Headers `json:"headers,omitempty"`
	Path            string  `json:"path"`
}

type QUICSettingsHeader struct {
	Type string `json:"type"`
}

type TLSSettings struct {
	AllowInsecure bool `json:"allowInsecure"`
}

type StreamSettings struct {
	Network     string       `json:"network"`
	Wssettings  Wssettings   `json:"wssettings"`
	Security    string       `json:"security,omitempty"`
	TLSSettings *TLSSettings `json:"tlsSettings,omitempty"`
}

type Outbounds struct {
	Mux            *Mux              `json:"mux,omitempty"`
	Protocol       string            `json:"protocol"`
	Settings       OutboundsSettings `json:"settings,omitempty"`
	StreamSettings *StreamSettings   `json:"streamSettings,omitempty"`
	Tag            string            `json:"tag"`
}
type Rules struct {
	IP          []string `json:"ip,omitempty"`
	OutboundTag string   `json:"outboundTag"`
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
}
type Routing struct {
	DomainStrategy string  `json:"domainStrategy"`
	Rules          []Rules `json:"rules"`
}
