package models

type CPEMatch struct {
	MatchCriteriaID string `json:"matchCriteriaId" gorm:"primaryKey;type:text;"`
	Criteria        string `json:"criteria" gorm:"type:text;"`
	Part            string `json:"part" gorm:"index;type:text;"`
	Vendor          string `json:"vendor" gorm:"index;type:text;"`
	Product         string `json:"product" gorm:"index;type:text;"`
	Version         string `json:"version" gorm:"index;type:text;"`
	Update          string `json:"update" gorm:"type:text;"`
	Edition         string `json:"edition" gorm:"type:text;"`
	Language        string `json:"language" gorm:"type:text;"`
	SwEdition       string `json:"swEdition" gorm:"type:text;"`
	TargetSw        string `json:"targetSw" gorm:"type:text;"`
	TargetHw        string `json:"targetHw" gorm:"type:text;"`
	Other           string `json:"other" gorm:"type:text;"`

	VersionEndExcluding   string `json:"versionEndExcluding" gorm:"index;type:text;"`
	VersionStartIncluding string `json:"versionStartIncluding" gorm:"index;type:text;"`

	Vulnerable bool `json:"vulnerable" gorm:"type:boolean;"`

	CVEs []*CVE `json:"cve" gorm:"many2many:cve_cpe_match;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
