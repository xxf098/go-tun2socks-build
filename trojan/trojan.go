package trojan

type OutboundsSettings struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	ServerName string `json:"serverName"` // sni
}
