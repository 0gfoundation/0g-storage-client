package node

// HotRouterDownloadRequest is the request body for POST /download to the hot storage router.
type HotRouterDownloadRequest struct {
	User      string `json:"user"`
	FileHash  string `json:"file_hash"`
	Nonce     uint64 `json:"nonce"`
	Signature string `json:"signature"`
}

// HotRouterDownloadResponse is the response from the hot storage router's /download endpoint.
type HotRouterDownloadResponse struct {
	NodeURL   string `json:"node_url"`
	Provider  string `json:"provider"`
	FileHash  string `json:"file_hash"`
	MaxFee    string `json:"max_fee"`
	Nonce     uint64 `json:"nonce"`
	Signature string `json:"signature"`
}

// HotRouterBalanceResponse is the response from the hot storage router's /balance endpoint.
type HotRouterBalanceResponse struct {
	Balance       string `json:"balance"`
	LocalReserved string `json:"local_reserved"`
	Available     string `json:"available"`
}

// HotRouterServiceResponse is the response from the hot storage router's /service endpoint.
type HotRouterServiceResponse struct {
	PricePerByte string `json:"price_per_byte"`
	URL          string `json:"url"`
	Active       bool   `json:"active"`
}

// HotDownloadResponse is the response from the hot storage node's hot_download RPC method.
type HotDownloadResponse struct {
	Data   string `json:"data"`
	FeeWei string `json:"feeWei"`
}
