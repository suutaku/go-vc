package status

const (
	currentStatusRevoked = "revoked"

	statusList2021Entry = "StatusList2021Entry"
)

// StatusList2021Entry
// https://w3c.github.io/vc-status-list-2021/#statuslist2021entry
type StatusEntry struct {
	ID         string `json:"id,omitempty"`
	Type       string `json:"type,omitempty"`
	Purpose    string `json:"statusPurpose"`
	ListIndex  string `json:"statusListIndex"`
	Credential string `json:"statusListCredential"`
}
