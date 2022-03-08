package settings

type ShadowsocksServerTarget struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Email    string `json:"email"`
	Level    byte   `json:"level"`
	OTA      bool   `json:"ota"`
}

type ShadowsocksOutboundsSettings struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}
