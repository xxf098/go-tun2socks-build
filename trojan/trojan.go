package trojan

type TrojanServerTarget struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Level    byte   `json:"level"`
}

type OutboundsSettings struct {
	Servers []*TrojanServerTarget `json:"servers"`
}
