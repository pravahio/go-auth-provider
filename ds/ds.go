package ds

type Access uint8
type ServiceType uint8

const (
	AccessNone Access = iota
	AccessRead
	AccessWrite
	AccessReadWrite

	ServiceTypeRealtime ServiceType = iota
	ServiceTypeHistorical
)

type Service struct {
	Type   ServiceType `json:"type"`
	Access Access      `json:"access"`
}

type Scope struct {
	Channel  string    `json:"channel"`
	Services []Service `json:"services"`
}

type Request struct {
	ClientId            string  `json:"client_id"`
	AuthenticationToken string  `json:"authentication_token"`
	Scopes              []Scope `json:"scopes"`
}

type AccessToken struct {
	Request   Request `json:"request"`
	ValidTill int64   `json:"valid_till"`
}

type SignedAccessToken struct {
	AccessToken AccessToken `json:"access_token"`
	R           []byte      `json:"r"`
	S           []byte      `json:"s"`
}
